package filters

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/types/trace"
)

const (
	maxBpfDataFilterStrSize = 256 // maximum str size supported by Data filter in BPF (MAX_DATA_FILTER_STR_SIZE)
)

type MatchTypes struct {
	exactMatch     bool
	notExactMatch  bool
	prefixMatch    bool
	notPrefixMatch bool
	suffixMatch    bool
	notSuffixMatch bool
}

// KernelDataFilter maps event IDs to data field filters,
// enabling or disabling each field at the kernel level
type KernelDataFilter struct {
	kernelFilters     map[events.ID]map[string]bool
	kernelMatchStates MatchTypes
}

func NewKernelDataFilter() *KernelDataFilter {
	return &KernelDataFilter{
		kernelFilters: make(map[events.ID]map[string]bool),
		kernelMatchStates: MatchTypes{
			exactMatch:     false,
			notExactMatch:  false,
			prefixMatch:    false,
			notPrefixMatch: false,
			suffixMatch:    false,
			notSuffixMatch: false,
		},
	}
}

// EnableKernelFilter sets the kernel filter flag for an event and field
func (kdf *KernelDataFilter) enableKernelFilter(eventID events.ID, field string) {
	if _, ok := kdf.kernelFilters[eventID]; !ok {
		kdf.kernelFilters[eventID] = make(map[string]bool)
	}
	kdf.kernelFilters[eventID][field] = true
}

// IsKernelFilterEnabled checks if the kernel filter flag is enabled for an event and field
func (kdf *KernelDataFilter) IsKernelFilterEnabled(eventID events.ID, field string) bool {
	if fields, ok := kdf.kernelFilters[eventID]; ok {
		return fields[field]
	}
	return false
}

type DataFilter struct {
	filters          map[events.ID]map[string]Filter[*StringFilter]
	kernelDataFilter *KernelDataFilter
	enabled          bool
}

// Compile-time check to ensure that DataFilter implements the Cloner interface
var _ utils.Cloner[*DataFilter] = &DataFilter{}

func NewDataFilter() *DataFilter {
	return &DataFilter{
		filters:          map[events.ID]map[string]Filter[*StringFilter]{},
		enabled:          false,
		kernelDataFilter: NewKernelDataFilter(),
	}
}

type KernelDataFields struct {
	ID     events.ID
	String string
}

type KernelDataFilterEqualities struct {
	ExactEqual     map[KernelDataFields]struct{}
	ExactNotEqual  map[KernelDataFields]struct{}
	PrefixEqual    map[KernelDataFields]struct{}
	PrefixNotEqual map[KernelDataFields]struct{}
	SuffixEqual    map[KernelDataFields]struct{}
	SuffixNotEqual map[KernelDataFields]struct{}
}

func (df *DataFilter) Equalities() KernelDataFilterEqualities {
	if !df.Enabled() {
		return KernelDataFilterEqualities{
			ExactEqual:     map[KernelDataFields]struct{}{},
			ExactNotEqual:  map[KernelDataFields]struct{}{},
			PrefixEqual:    map[KernelDataFields]struct{}{},
			PrefixNotEqual: map[KernelDataFields]struct{}{},
			SuffixEqual:    map[KernelDataFields]struct{}{},
			SuffixNotEqual: map[KernelDataFields]struct{}{},
		}
	}

	combinedEqualities := make(map[KernelDataFields]struct{})
	combinedNotEqualities := make(map[KernelDataFields]struct{})
	combinedPrefixEqualities := make(map[KernelDataFields]struct{})
	combinedNotPrefixEqualities := make(map[KernelDataFields]struct{})
	combinedSuffixEqualities := make(map[KernelDataFields]struct{})
	combinedNotSuffixEqualities := make(map[KernelDataFields]struct{})

	// selected data name
	dataField := "pathname"

	for eventID := range df.kernelDataFilter.kernelFilters {
		filterMap, ok := df.filters[eventID]
		if !ok {
			continue
		}

		fieldName, ok := filterMap[dataField]
		if !ok {
			continue
		}

		filter, ok := fieldName.(*StringFilter)
		if !ok {
			continue
		}
		equalities := filter.Equalities()

		// Merge the equalities and not-equalities into the combined maps
		// Exact match
		for k := range equalities.ExactEqual {
			combinedEqualities[KernelDataFields{eventID, k}] = struct{}{}
			df.kernelDataFilter.kernelMatchStates.exactMatch = true
		}
		for k := range equalities.ExactNotEqual {
			combinedNotEqualities[KernelDataFields{eventID, k}] = struct{}{}
			df.kernelDataFilter.kernelMatchStates.notExactMatch = true
			df.kernelDataFilter.kernelMatchStates.exactMatch = true
		}

		// Prefix match
		for k := range equalities.PrefixEqual {
			combinedPrefixEqualities[KernelDataFields{eventID, k}] = struct{}{}
			df.kernelDataFilter.kernelMatchStates.prefixMatch = true
		}
		for k := range equalities.PrefixNotEqual {
			combinedNotPrefixEqualities[KernelDataFields{eventID, k}] = struct{}{}
			df.kernelDataFilter.kernelMatchStates.notPrefixMatch = true
			df.kernelDataFilter.kernelMatchStates.prefixMatch = true
		}

		// Suffix match
		for k := range equalities.SuffixEqual {
			reversed := utils.ReverseString(k)
			combinedSuffixEqualities[KernelDataFields{eventID, reversed}] = struct{}{}
			df.kernelDataFilter.kernelMatchStates.suffixMatch = true
		}
		for k := range equalities.SuffixNotEqual {
			reversed := utils.ReverseString(k)
			combinedNotSuffixEqualities[KernelDataFields{eventID, reversed}] = struct{}{}
			df.kernelDataFilter.kernelMatchStates.notSuffixMatch = true
			df.kernelDataFilter.kernelMatchStates.suffixMatch = true
		}
	}

	return KernelDataFilterEqualities{
		ExactEqual:     combinedEqualities,
		ExactNotEqual:  combinedNotEqualities,
		PrefixEqual:    combinedPrefixEqualities,
		PrefixNotEqual: combinedNotPrefixEqualities,
		SuffixEqual:    combinedSuffixEqualities,
		SuffixNotEqual: combinedNotSuffixEqualities,
	}
}

// GetEventFilters returns the data filters map for a specific event
// writing to the map may have unintentional consequences, avoid doing so
func (df *DataFilter) GetEventFilters(eventID events.ID) map[string]Filter[*StringFilter] {
	return df.filters[eventID]
}

func (df *DataFilter) Filter(eventID events.ID, data []trace.Argument) bool {
	if !df.Enabled() {
		return true
	}

	// No need to filter the following event IDs as they have already
	// been filtered in the kernel
	if df.kernelDataFilter.IsKernelFilterEnabled(eventID, "pathname") {
		return true
	}

	// TODO: remove once events params are introduced
	//       i.e. print_mem_dump.params.symbol_name=system:security_file_open
	// events.PrintMemDump bypass was added due to issue #2546
	// because it uses usermode applied filters as parameters for the event,
	// which occurs after filtering
	if eventID == events.PrintMemDump {
		return true
	}

	for dataName, f := range df.filters[eventID] {
		found := false
		var dataVal interface{}

		for _, d := range data {
			if d.Name == dataName {
				found = true
				dataVal = d.Value
				break
			}
		}
		if !found {
			return false
		}

		// TODO: use type assertion instead of string conversion
		dataVal = fmt.Sprint(dataVal)

		res := f.Filter(dataVal)
		if !res {
			return false
		}
	}

	return true
}

func (df *DataFilter) Parse(filterName string, operatorAndValues string, eventsNameToID map[string]events.ID) error {
	// Event data filter has the following format: "event.data.dataname=dataval"
	// filterName have the format event.dataname, and operatorAndValues have the format "=dataval"
	parts := strings.Split(filterName, ".")
	if len(parts) != 3 {
		return InvalidExpression(filterName + operatorAndValues)
	}
	// option "args" will be deprecate in future
	if (parts[1] != "data") && (parts[1] != "args") {
		return InvalidExpression(filterName + operatorAndValues)
	}

	eventName := parts[0]
	dataName := parts[2]

	if eventName == "" || dataName == "" {
		return InvalidExpression(filterName + operatorAndValues)
	}

	id, ok := eventsNameToID[eventName]
	if !ok {
		return InvalidEventName(eventName)
	}

	if !events.Core.IsDefined(id) {
		return InvalidEventName(eventName)
	}
	eventDefinition := events.Core.GetDefinitionByID(id)
	eventFields := eventDefinition.GetFields()

	// check if data name exists for this event
	dataFound := false
	for i := range eventFields {
		if eventFields[i].Name == dataName {
			dataFound = true
			break
		}
	}

	// if the event is a signature event, we allow filtering on dynamic argument
	if !dataFound && !eventDefinition.IsSignature() {
		return InvalidEventData(dataName)
	}

	// valueHandler is passed to the filter constructor to allow for custom value handling
	// before the filter is applied
	valueHandler := func(val string) (string, error) {
		switch id {
		case events.SecurityFileOpen,
			events.MagicWrite,
			events.SecurityMmapFile:
			return df.processKernelFilter(id, val, dataName)

		case events.SysEnter,
			events.SysExit,
			events.SuspiciousSyscallSource:
			if dataName == "syscall" { // handle either syscall name or syscall id
				_, err := strconv.Atoi(val)
				if err != nil {
					// if val is a syscall name, then we need to convert it to a syscall id
					syscallID, ok := events.Core.GetDefinitionIDByName(val)
					if !ok {
						return val, errfmt.Errorf("invalid syscall name: %s", val)
					}
					val = strconv.Itoa(int(syscallID))
				}
			}
		case events.HookedSyscall:
			if dataName == "syscall" { // handle either syscall name or syscall id
				dataEventID, err := strconv.Atoi(val)
				if err == nil {
					// if val is a syscall id, then we need to convert it to a syscall name
					val = events.Core.GetDefinitionByID(events.ID(dataEventID)).GetName()
				}
			}
		}

		return val, nil
	}

	err := df.parseFilter(id, dataName, operatorAndValues,
		func() Filter[*StringFilter] {
			// TODO: map data type to an appropriate filter constructor
			return NewStringFilter(valueHandler)
		})
	if err != nil {
		return errfmt.WrapError(err)
	}

	df.Enable()

	return nil
}

// parseFilter adds an data filter with the relevant filterConstructor
// The user must responsibly supply a reliable Filter object.
func (df *DataFilter) parseFilter(id events.ID, dataName string, operatorAndValues string, filterConstructor func() Filter[*StringFilter]) error {
	if _, ok := df.filters[id]; !ok {
		df.filters[id] = map[string]Filter[*StringFilter]{}
	}

	if _, ok := df.filters[id][dataName]; !ok {
		// store new event data filter if missing
		dataFilter := filterConstructor()
		df.filters[id][dataName] = dataFilter
	}

	// extract the data filter and parse expression into it
	f := df.filters[id][dataName]
	err := f.Parse(operatorAndValues)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// store the data filter again
	df.filters[id][dataName] = f

	return nil
}

func (df *DataFilter) Enable() {
	df.enabled = true
	for _, filterMap := range df.filters {
		for _, f := range filterMap {
			f.Enable()
		}
	}
}

func (df *DataFilter) processKernelFilter(id events.ID, val, dataName string) (string, error) {
	// Check for kernel filter restrictions
	if err := df.checkKernelFilterRestrictions(val); err != nil {
		return val, err
	}

	// Enable the kernel filter if restrictions are satisfied
	df.enableKernelFilterArg(id, dataName)
	return val, nil
}

// CheckKernelFilterRestrictions enforces restrictions for kernel-filtered
// fields: 1) values cannot use "contains" (e.g., start and end with "*");
// and 2) Maximum length for the value is 255 characters.
func (df *DataFilter) checkKernelFilterRestrictions(val string) error {
	if len(val) == 0 {
		return InvalidValue("empty value is not allowed")
	}

	// Disallow "*" and "**" as invalid values
	if val == "*" || val == "**" {
		return InvalidValue(val)
	}

	// Check for "contains" type filtering
	if len(val) > 1 && val[0] == '*' && val[len(val)-1] == '*' {
		return InvalidFilterType()
	}

	// Enforce maximum length restriction
	trimmedVal := strings.Trim(val, "*")
	if len(trimmedVal) > maxBpfDataFilterStrSize-1 {
		return InvalidValueMax(val, maxBpfDataFilterStrSize-1)
	}
	return nil
}

// enableKernelFilterArg activates a kernel filter for the specified event and data field.
// This function currently supports enabling filters for the "pathname" field only.
func (df *DataFilter) enableKernelFilterArg(id events.ID, dataName string) {
	if dataName != "pathname" {
		return
	}

	filterMap, ok := df.filters[id]
	if !ok {
		return
	}

	fieldName, ok := filterMap[dataName]
	if !ok {
		return
	}

	strFilter, ok := fieldName.(*StringFilter)
	if !ok {
		return
	}

	strFilter.Enable()
	df.kernelDataFilter.enableKernelFilter(id, dataName)
}

func (df *DataFilter) Disable() {
	df.enabled = false
	for _, filterMap := range df.filters {
		for _, f := range filterMap {
			f.Disable()
		}
	}
}

func (df *DataFilter) Enabled() bool {
	return df.enabled
}

func (df *DataFilter) EnabledExcatMatch() bool {
	return df.kernelDataFilter.kernelMatchStates.exactMatch
}

func (df *DataFilter) EnabledPrefixMatch() bool {
	return df.kernelDataFilter.kernelMatchStates.prefixMatch
}

func (df *DataFilter) EnabledSuffixMatch() bool {
	return df.kernelDataFilter.kernelMatchStates.suffixMatch
}

func (df *DataFilter) MatchIfKeyMissingExcatMatch() bool {
	return df.kernelDataFilter.kernelMatchStates.notExactMatch
}

func (df *DataFilter) MatchIfKeyMissingPrefixMatch() bool {
	return df.kernelDataFilter.kernelMatchStates.notPrefixMatch
}

func (df *DataFilter) MatchIfKeyMissingSuffixMatch() bool {
	return df.kernelDataFilter.kernelMatchStates.notSuffixMatch
}

func (df *DataFilter) Clone() *DataFilter {
	if df == nil {
		return nil
	}

	n := NewDataFilter()

	for eventID, filterMap := range df.filters {
		n.filters[eventID] = map[string]Filter[*StringFilter]{}
		for dataName, f := range filterMap {
			n.filters[eventID][dataName] = f.Clone()
		}
	}

	n.enabled = df.enabled

	return n
}
