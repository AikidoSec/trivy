package parser

import (
	"context"
	"errors"
	"io/fs"
	"maps"
	"reflect"
	"slices"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/typeexpr"
	"github.com/samber/lo"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"

	"github.com/aquasecurity/trivy/pkg/iac/ignore"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	tfcontext "github.com/aquasecurity/trivy/pkg/iac/terraform/context"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	maxContextIterations = 32
)

type evaluator struct {
	logger            *log.Logger
	filesystem        fs.FS
	ctx               *tfcontext.Context
	blocks            terraform.Blocks
	inputVars         map[string]cty.Value
	moduleMetadata    *modulesMetadata
	projectRootPath   string // root of the current scan
	modulePath        string
	moduleName        string
	ignores           ignore.Rules
	parentParser      *Parser
	allowDownloads    bool
	skipCachedModules bool
}

func newEvaluator(
	target fs.FS,
	parentParser *Parser,
	projectRootPath string,
	modulePath string,
	workingDir string,
	moduleName string,
	blocks terraform.Blocks,
	inputVars map[string]cty.Value,
	moduleMetadata *modulesMetadata,
	workspace string,
	ignores ignore.Rules,
	logger *log.Logger,
	allowDownloads bool,
	skipCachedModules bool,
) *evaluator {

	// create a context to store variables and make functions available
	ctx := tfcontext.NewContext(&hcl.EvalContext{
		Functions: Functions(target, modulePath),
	}, nil)

	// these variables are made available by terraform to each module
	ctx.SetByDot(cty.StringVal(workspace), "terraform.workspace")
	ctx.SetByDot(cty.StringVal(projectRootPath), "path.root")
	ctx.SetByDot(cty.StringVal(modulePath), "path.module")
	ctx.SetByDot(cty.StringVal(workingDir), "path.cwd")

	// each block gets its own scope to define variables in
	for _, b := range blocks {
		b.OverrideContext(ctx.NewChild())
	}

	return &evaluator{
		filesystem:        target,
		parentParser:      parentParser,
		modulePath:        modulePath,
		moduleName:        moduleName,
		projectRootPath:   projectRootPath,
		ctx:               ctx,
		blocks:            blocks,
		inputVars:         inputVars,
		moduleMetadata:    moduleMetadata,
		ignores:           ignores,
		logger:            logger,
		allowDownloads:    allowDownloads,
		skipCachedModules: skipCachedModules,
	}
}

func (e *evaluator) evaluateStep() {

	e.ctx.Set(e.getValuesByBlockType("variable"), "var")
	e.ctx.Set(e.getValuesByBlockType("locals"), "local")
	e.ctx.Set(e.getValuesByBlockType("provider"), "provider")

	for typ, resource := range e.getResources() {
		e.ctx.Set(resource, typ)
	}

	e.ctx.Set(e.getValuesByBlockType("data"), "data")
	e.ctx.Set(e.getValuesByBlockType("output"), "output")
	e.ctx.Set(e.getValuesByBlockType("module"), "module")
}

// exportOutputs is used to export module outputs to the parent module
func (e *evaluator) exportOutputs() cty.Value {
	data := make(map[string]cty.Value)
	for _, block := range e.blocks.OfType("output") {
		attr := block.GetAttribute("value")
		if attr.IsNil() {
			continue
		}
		data[block.Label()] = attr.Value()
		e.logger.Debug(
			"Added module output",
			log.String("block", block.Label()),
			log.String("value", attr.Value().GoString()),
		)
	}
	return cty.ObjectVal(data)
}

func (e *evaluator) EvaluateAll(ctx context.Context) (terraform.Modules, map[string]fs.FS) {

	e.logger.Debug("Starting module evaluation...", log.String("path", e.modulePath))

	fsKey := types.CreateFSKey(e.filesystem)
	fsMap := map[string]fs.FS{
		fsKey: e.filesystem,
	}

	e.evaluateSteps()

	// expand out resources and modules via count, for-each and dynamic
	// (not a typo, we do this twice so every order is processed)
	// TODO: using a module in for_each or count does not work,
	// because the child module is evaluated later
	e.blocks = e.expandBlocks(e.blocks)
	e.blocks = e.expandBlocks(e.blocks)

	// Re-evaluate locals after all expansions to ensure computed locals
	// that depend on expanded resources get the correct values
	e.ctx.Replace(e.getValuesByBlockType("locals"), "local")

	// Final expansion round to handle any previously deferred for_each blocks
	// that now have correct local values
	e.blocks = e.expandBlockForEaches(e.blocks)

	// rootModule is initialized here, but not fully evaluated until all submodules are evaluated.
	// Initializing it up front to keep the module hierarchy of parents correct.
	rootModule := terraform.NewModule(e.projectRootPath, e.modulePath, e.blocks, e.ignores)
	submodules := e.evaluateSubmodules(ctx, rootModule, fsMap)

	e.logger.Debug("Starting post-submodules evaluation...")
	e.evaluateSteps()

	e.logger.Debug("Module evaluation complete.")
	return append(terraform.Modules{rootModule}, submodules...), fsMap
}

func (e *evaluator) evaluateSubmodules(ctx context.Context, parent *terraform.Module, fsMap map[string]fs.FS) terraform.Modules {
	submodules := e.loadSubmodules(ctx)

	if len(submodules) == 0 {
		return nil
	}

	e.logger.Debug("Starting submodules evaluation...")

	for i := range maxContextIterations {
		changed := false
		for _, sm := range submodules {
			changed = changed || e.evaluateSubmodule(ctx, sm)
		}
		if !changed {
			e.logger.Debug("All submodules are evaluated", log.Int("loop", i))
			break
		}
	}

	e.logger.Debug("Starting post-submodule evaluation...")
	e.evaluateSteps()

	var modules terraform.Modules
	for _, sm := range submodules {
		// Assign the parent placeholder to any submodules without a parent. Any modules
		// with a parent already have their correct parent placeholder assigned.
		for _, submod := range sm.modules {
			if submod.Parent() == nil {
				submod.SetParent(parent)
			}
		}

		modules = append(modules, sm.modules...)
		maps.Copy(fsMap, sm.fsMap)
	}

	e.logger.Debug("Finished processing submodule(s).", log.Int("count", len(modules)))
	return modules
}

type submodule struct {
	definition *ModuleDefinition
	eval       *evaluator
	modules    terraform.Modules
	lastState  map[string]cty.Value
	fsMap      map[string]fs.FS
}

func (e *evaluator) loadSubmodules(ctx context.Context) []*submodule {
	var submodules []*submodule

	for _, definition := range e.loadModules(ctx) {
		eval, err := definition.Parser.Load(ctx)
		if errors.Is(err, ErrNoFiles) {
			continue
		} else if err != nil {
			e.logger.Error("Failed to load submodule", log.String("name", definition.Name), log.Err(err))
			continue
		}

		submodules = append(submodules, &submodule{
			definition: definition,
			eval:       eval,
			fsMap:      make(map[string]fs.FS),
		})
	}

	return submodules
}

func (e *evaluator) evaluateSubmodule(ctx context.Context, sm *submodule) bool {
	inputVars := sm.definition.inputVars()
	if len(sm.modules) > 0 {
		if reflect.DeepEqual(inputVars, sm.lastState) {
			e.logger.Debug("Submodule inputs unchanged", log.String("name", sm.definition.Name))
			return false
		}
	}

	e.logger.Debug("Evaluating submodule", log.String("name", sm.definition.Name))
	sm.eval.inputVars = inputVars
	sm.modules, sm.fsMap = sm.eval.EvaluateAll(ctx)
	outputs := sm.eval.exportOutputs()

	valueMap := e.ctx.Get("module").AsValueMap()
	if valueMap == nil {
		valueMap = make(map[string]cty.Value)
	}

	// lastState needs to be captured after applying outputs – so that they
	// don't get treated as changes – but before running post-submodule
	// evaluation, so that changes from that can trigger re-evaluations of
	// the submodule if/when they feed back into inputs.
	ref := sm.definition.Definition.Reference()
	e.ctx.Set(blockInstanceValues(sm.definition.Definition, valueMap, outputs), "module", ref.NameLabel())
	e.ctx.Set(outputs, "module", sm.definition.Name)
	sm.lastState = sm.definition.inputVars()
	e.evaluateSteps()
	return true
}

func (e *evaluator) evaluateSteps() {
	var lastContext hcl.EvalContext
	for i := range maxContextIterations {

		e.logger.Debug("Starting iteration", log.Int("iteration", i))
		e.evaluateStep()

		// if ctx matches the last evaluation, we can bail, nothing left to resolve
		if i > 0 && reflect.DeepEqual(lastContext.Variables, e.ctx.Inner().Variables) {
			e.logger.Debug("Context unchanged", log.Int("iteration", i))
			break
		}
		if len(e.ctx.Inner().Variables) != len(lastContext.Variables) {
			lastContext.Variables = make(map[string]cty.Value, len(e.ctx.Inner().Variables))
		}
		maps.Copy(lastContext.Variables, e.ctx.Inner().Variables)
	}
}

func (e *evaluator) expandBlocks(blocks terraform.Blocks) terraform.Blocks {
	return e.expandDynamicBlocks(e.expandBlockForEaches(e.expandBlockCounts(blocks))...)
}

func (e *evaluator) expandDynamicBlocks(blocks ...*terraform.Block) terraform.Blocks {
	for _, b := range blocks {
		if err := b.ExpandBlock(); err != nil {
			e.logger.Debug(`Failed to expand dynamic block.`,
				log.String("block", b.FullName()), log.Err(err))
		}
	}
	return blocks
}

func isBlockSupportsForEachMetaArgument(block *terraform.Block) bool {
	return slices.Contains([]string{
		"module",
		"resource",
		"data",
	}, block.Type())
}

func (e *evaluator) expandBlockForEaches(blocks terraform.Blocks) terraform.Blocks {

	var forEachFiltered terraform.Blocks

	for _, block := range blocks {

		forEachAttr := block.GetAttribute("for_each")

		if forEachAttr.IsNil() || block.IsExpanded() || !isBlockSupportsForEachMetaArgument(block) || e.shouldDeferForEachExpansion(forEachAttr) {
			forEachFiltered = append(forEachFiltered, block)
			continue
		}

		forEachVal := forEachAttr.Value()

		if forEachVal.IsNull() || !forEachVal.IsKnown() || !forEachAttr.IsIterable() {
			e.logger.Debug(`Failed to expand block. Invalid "for-each" argument. Must be known and iterable.`,
				log.String("block", block.FullName()),
				log.String("value", forEachVal.GoString()),
			)
			continue
		}

		clones := make(map[string]cty.Value)
		_ = forEachAttr.Each(func(key cty.Value, val cty.Value) {

			if val.IsNull() {
				return
			}

			// instances are identified by a map key (or set member) from the value provided to for_each
			idx, err := convert.Convert(key, cty.String)
			if err != nil {
				e.logger.Debug(
					`Failed to expand block. Invalid "for-each" argument: map key (or set value) is not a string`,
					log.String("block", block.FullName()),
					log.String("key", key.GoString()),
					log.String("value", val.GoString()),
					log.Err(err),
				)
				return
			}

			// if the argument is a collection but not a map, then the resource identifier
			// is the value of the collection. The exception is the use of for-each inside a dynamic block,
			// because in this case the collection element may not be a primitive value.
			if (forEachVal.Type().IsCollectionType() || forEachVal.Type().IsTupleType()) &&
				!forEachVal.Type().IsMapType() {
				stringVal, err := convert.Convert(val, cty.String)
				if err != nil {
					e.logger.Debug(
						"Failed to expand block. Invalid 'for-each' argument: value is not a string",
						log.String("block", block.FullName()),
						log.String("key", idx.AsString()),
						log.String("value", val.GoString()),
						log.Err(err),
					)
					return
				}
				idx = stringVal
			}

			clone := block.Clone(idx)
			ctx := clone.Context()
			e.copyVariables(block, clone)

			eachObj := cty.ObjectVal(map[string]cty.Value{
				"key":   idx,
				"value": val,
			})

			ctx.Set(eachObj, "each")
			ctx.Set(eachObj, block.TypeLabel())
			forEachFiltered = append(forEachFiltered, clone)
			clones[idx.AsString()] = clone.Values()
		})

		metadata := block.GetMetadata()
		if len(clones) == 0 {
			e.ctx.SetByDot(cty.EmptyTupleVal, metadata.Reference())
		} else {
			// The for-each meta-argument creates multiple instances of the resource that are stored in the map.
			// So we must replace the old resource with a map with the attributes of the resource.
			e.ctx.Replace(cty.ObjectVal(clones), metadata.Reference())
		}
		e.logger.Debug("Expanded block into clones via 'for_each' attribute.",
			log.String("block", block.FullName()),
			log.Int("clones", len(clones)),
		)
	}

	return forEachFiltered
}

func isBlockSupportsCountMetaArgument(block *terraform.Block) bool {
	return slices.Contains([]string{
		"module",
		"resource",
		"data",
	}, block.Type())
}

func (e *evaluator) expandBlockCounts(blocks terraform.Blocks) terraform.Blocks {
	var countFiltered terraform.Blocks
	for _, block := range blocks {
		countAttr := block.GetAttribute("count")
		if countAttr.IsNil() || block.IsExpanded() || !isBlockSupportsCountMetaArgument(block) {
			countFiltered = append(countFiltered, block)
			continue
		}
		count := 1
		countAttrVal := countAttr.Value()
		if !countAttrVal.IsNull() && countAttrVal.IsKnown() && countAttrVal.Type() == cty.Number {
			count = int(countAttr.AsNumber())
		}

		var clones []cty.Value
		for i := 0; i < count; i++ {
			clone := block.Clone(cty.NumberIntVal(int64(i)))
			clones = append(clones, clone.Values())
			countFiltered = append(countFiltered, clone)
			metadata := clone.GetMetadata()
			e.ctx.SetByDot(clone.Values(), metadata.Reference())
		}
		metadata := block.GetMetadata()
		if len(clones) == 0 {
			e.ctx.SetByDot(cty.EmptyTupleVal, metadata.Reference())
		} else {
			e.ctx.SetByDot(cty.TupleVal(clones), metadata.Reference())
		}
		e.logger.Debug(
			"Expanded block into clones via 'count' attribute.",
			log.String("block", block.FullName()),
			log.Int("clones", len(clones)),
		)
	}

	return countFiltered
}

func (e *evaluator) copyVariables(from, to *terraform.Block) {

	var fromBase string
	var fromRel string
	var toRel string

	switch from.Type() {
	case "resource":
		fromBase = from.TypeLabel()
		fromRel = from.NameLabel()
		toRel = to.NameLabel()
	case "module":
		fromBase = from.Type()
		fromRel = from.TypeLabel()
		toRel = to.TypeLabel()
	default:
		return
	}

	rootCtx := e.ctx.Root()
	srcValue := rootCtx.Get(fromBase, fromRel)
	if srcValue == cty.NilVal {
		return
	}
	rootCtx.Set(srcValue, fromBase, toRel)
}

func (e *evaluator) evaluateVariable(b *terraform.Block) (cty.Value, error) {
	if b.Label() == "" {
		return cty.NilVal, errors.New("empty label - cannot resolve")
	}

	attributes := b.Attributes()

	var valType cty.Type
	var defaults *typeexpr.Defaults
	if typeAttr, exists := attributes["type"]; exists {
		ty, def, err := typeAttr.DecodeVarType()
		if err != nil {
			return cty.NilVal, err
		}
		valType = ty
		defaults = def
	}

	var val cty.Value

	if override, exists := e.inputVars[b.Label()]; exists && override.Type() != cty.NilType {
		val = override
	} else if def, exists := attributes["default"]; exists {
		val = def.NullableValue()
	} else {
		return cty.NilVal, errors.New("no value found")
	}

	if valType != cty.NilType {
		if defaults != nil {
			val = defaults.Apply(val)
		}

		typedVal, err := convert.Convert(val, valType)
		if err != nil {
			return cty.NilVal, err
		}
		return typedVal, nil
	}

	return val, nil

}

func (e *evaluator) evaluateOutput(b *terraform.Block) (cty.Value, error) {
	if b.Label() == "" {
		return cty.NilVal, errors.New("empty label - cannot resolve")
	}

	attribute := b.GetAttribute("value")
	if attribute.IsNil() {
		return cty.NilVal, errors.New("cannot resolve output with no attributes")
	}
	return attribute.Value(), nil
}

// returns true if all evaluations were successful
func (e *evaluator) getValuesByBlockType(blockType string) cty.Value {

	blocksOfType := e.blocks.OfType(blockType)
	values := make(map[string]cty.Value)

	for _, b := range blocksOfType {
		switch b.Type() {
		case "variable": // variables are special in that their value comes from the "default" attribute
			val, err := e.evaluateVariable(b)
			if err != nil {
				continue
			}
			values[b.Label()] = val
		case "output":
			val, err := e.evaluateOutput(b)
			if err != nil {
				continue
			}
			values[b.Label()] = val
		case "locals", "moved", "import":
			localValues := b.Values().AsValueMap()
			maps.Copy(values, localValues)
		case "provider", "module", "check":
			if b.Label() == "" {
				continue
			}
			values[b.Label()] = b.Values()
		case "data":
			if len(b.Labels()) < 2 {
				continue
			}

			// Data blocks should all be loaded into the top level 'values'
			// object. The hierarchy of the map is:
			//  values = map[<type>]map[<name>] =
			//              Block -> Block's attributes as a cty.Object
			//              Tuple(Block) -> Instances of the block
			//              Object(Block) -> Field values are instances of the block
			ref := b.Reference()
			typeValues, ok := values[ref.TypeLabel()]
			if !ok {
				typeValues = cty.ObjectVal(make(map[string]cty.Value))
				values[ref.TypeLabel()] = typeValues
			}

			valueMap := typeValues.AsValueMap()
			if valueMap == nil {
				valueMap = make(map[string]cty.Value)
			}
			valueMap[ref.NameLabel()] = blockInstanceValues(b, valueMap, b.Values())

			// Update the map of all blocks with the same type.
			values[ref.TypeLabel()] = cty.ObjectVal(valueMap)
		}
	}

	return cty.ObjectVal(values)
}

func (e *evaluator) getResources() map[string]cty.Value {
	values := make(map[string]map[string]cty.Value)

	for _, b := range e.blocks {
		if b.Type() != "resource" || len(b.Labels()) < 2 {
			continue
		}

		ref := b.Reference()
		typeValues, exists := values[ref.TypeLabel()]
		if !exists {
			typeValues = make(map[string]cty.Value)
			values[ref.TypeLabel()] = typeValues
		}

		instanceVal := blockInstanceValues(b, typeValues, b.Values())
		typeValues[ref.NameLabel()] = instanceVal
	}

	result := lo.MapValues(values, func(v map[string]cty.Value, _ string) cty.Value {
		return cty.ObjectVal(v)
	})

	return result
}

// blockInstanceValues returns a cty.Value containing the values of the block instances.
// If the count argument is used, a tuple is returned where the index corresponds to the argument index.
// If the for_each argument is used, an object is returned where the key corresponds to the argument key.
// In other cases, the values of the block itself are returned.
func blockInstanceValues(b *terraform.Block, typeValues map[string]cty.Value, values cty.Value) cty.Value {
	ref := b.Reference()
	key := ref.RawKey()

	switch {
	case key.Type().Equals(cty.Number) && b.GetAttribute("count") != nil:
		idx, _ := key.AsBigFloat().Int64()
		return insertTupleElement(typeValues[ref.NameLabel()], int(idx), values)
	case isForEachKey(key) && b.GetAttribute("for_each") != nil:
		keyStr := ref.Key()

		instancesVal, exists := typeValues[ref.NameLabel()]
		if !exists || !instancesVal.CanIterateElements() {
			instancesVal = cty.EmptyObjectVal
		}

		instances := instancesVal.AsValueMap()
		if instances == nil {
			instances = make(map[string]cty.Value)
		}

		instances[keyStr] = values
		return cty.ObjectVal(instances)
	default:
		return values
	}
}

func isForEachKey(key cty.Value) bool {
	return key.Type().Equals(cty.Number) || key.Type().Equals(cty.String)
}

func (e *evaluator) shouldDeferForEachExpansion(forEachAttr *terraform.Attribute) bool {
	// Check if the for_each references a local value
	for _, ref := range forEachAttr.AllReferences() {
		if ref.BlockType().Name() == "locals" {
			// Get the local value from context
			localName := ref.NameLabel()
			if localVal := e.ctx.Get("local", localName); localVal != cty.NilVal && localVal.IsKnown() {
				// Check if this local contains unresolved dynamic values or looks like
				// it was computed from a single resource object instead of an expanded collection
				if e.localHasDynamicValues(localVal) {
					return true
				}
			}
		}
	}
	return false
}

func (e *evaluator) localHasDynamicValues(localVal cty.Value) bool {
	if !localVal.Type().IsObjectType() {
		return false
	}

	valueMap := localVal.AsValueMap()
	if valueMap == nil {
		return false
	}

	// Check if the local contains DynamicVal which indicates unresolved references
	for _, val := range valueMap {
		if val.Type() == cty.DynamicPseudoType {
			return true
		}

		// If it's an object, check recursively for dynamic values
		if val.Type().IsObjectType() {
			if subMap := val.AsValueMap(); subMap != nil {
				for _, subVal := range subMap {
					if subVal.Type() == cty.DynamicPseudoType {
						return true
					}
				}
			}
		}
	}

	return false
}
