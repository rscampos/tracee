package policy

import (
	"strings"

	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils"
)

// equality mirrors the C struct equality (eq_t).
// Check it for more info.
type equality struct {
	equalInPolicies       uint64
	equalitySetInPolicies uint64
}

const (
	// 8 bytes for equalInPolicies and 8 bytes for equalitySetInPolicies
	equalityValueSize = 16
)

// filtersEqualities stores the equalities for each filter in the policies
type filtersEqualities struct {
	uidEqualities         map[uint64]equality
	pidEqualities         map[uint64]equality
	mntNSEqualities       map[uint64]equality
	pidNSEqualities       map[uint64]equality
	cgroupIdEqualities    map[uint64]equality
	utsEqualities         map[string]equality
	commEqualities        map[string]equality
	dataEqualitiesPrefix  map[filters.KernelData]equality
	dataEqualitiesSuffix  map[filters.KernelData]equality
	dataEqualitiesExactly map[filters.KernelData]equality
	binaryEqualities      map[filters.NSBinary]equality
}

// equalityType represents the type of equality.
type equalityType int

const (
	notEqual equalityType = iota
	equal
)

// equalUpdater updates the equality with the given policyID.
type equalityUpdater func(eq *equality, policyID uint)

// notEqualUpdate updates the equality as not equal with the given policyID.
func notEqualUpdate(eq *equality, policyID uint) {
	// NotEqual == 0, so clear n bitmap bit
	utils.ClearBit(&eq.equalInPolicies, policyID)
	utils.SetBit(&eq.equalitySetInPolicies, policyID)
}

// equalUpdate updates the equality as equal with the given policyID.
func equalUpdate(eq *equality, policyID uint) {
	// Equal == 1, so set n bitmap bit
	utils.SetBit(&eq.equalInPolicies, policyID)
	utils.SetBit(&eq.equalitySetInPolicies, policyID)
}

// updateEqualities updates the equalities map with the given filter equalities
// for the given equality type and policy ID.
func updateEqualities[T comparable](
	equalitiesMap map[T]equality,
	filterEqualities map[T]struct{},
	eqType equalityType,
	policyID uint,
) {
	var update equalityUpdater

	switch eqType {
	case notEqual:
		update = notEqualUpdate
	case equal:
		update = equalUpdate
	default:
		logger.Errorw("Invalid equality type", "type", eqType)
		return
	}

	for k := range filterEqualities {
		eq, ok := equalitiesMap[k]
		if !ok {
			eq = equality{} // initialize if not exists
		}
		update(&eq, policyID) // update the equality
		equalitiesMap[k] = eq // update the map
	}
}

// updateAffixEqualities updates the equalities map with the given filter equalities
// for the specified equality type and policy ID. It handles corner cases where paths
// in the prefix/suffix filter are substrings of existing paths in the equalities map.
// In cases where one prefix/suffix path overlaps with another, their equality bitmaps
// are combined, addressing the corner case. This ensures that a single lookup retrieves
// the longest matching path, with equality bitmaps merged from overlapping policies.
func updateAffixEqualities[T comparable](
	equalitiesMap map[T]equality,
	filterEqualities map[T]struct{},
	eqType equalityType,
	policyID uint,
) {
	var update equalityUpdater

	switch eqType {
	case notEqual:
		update = notEqualUpdate
	case equal:
		update = equalUpdate
	default:
		logger.Errorw("Invalid equality type", "type", eqType)
		return
	}

	for newK := range filterEqualities {
		newEq, exists := equalitiesMap[newK]
		if !exists {
			newEq = equality{} // initialize if not exists
		}

		newKD, isKernelData := any(newK).(filters.KernelData)

		var longestMatch filters.KernelData
		var longestMatchEq equality

		if isKernelData {
			for existingK, existingEq := range equalitiesMap {
				existingKD, isExistingKernelData := any(existingK).(filters.KernelData)
				// skip if event ID is different
				if !isExistingKernelData || existingKD.ID != newKD.ID {
					continue
				}

				// check if exists a substrings of existing paths in the equalities map
				if strings.HasPrefix(existingKD.Path, newKD.Path) {
					// Directly update the equality if the new path is a prefix
					update(&existingEq, policyID)
					equalitiesMap[existingK] = existingEq
				} else if strings.HasPrefix(newKD.Path, existingKD.Path) {
					// Cache the longest match
					if len(existingKD.Path) > len(longestMatch.Path) {
						longestMatch = existingKD
						longestMatchEq = existingEq
					}
				}
			}

			// If a match was found, use the longest matching equality
			if longestMatch.Path != "" {
				newEq = longestMatchEq
			}
		}

		update(&newEq, policyID)    // update the equality
		equalitiesMap[newK] = newEq // update the map
	}
}

// computeFilterEqualities computes the equalities for each filter type in the policies
// updating the provided filtersEqualities struct.
func (ps *policies) computeFilterEqualities(
	fEqs *filtersEqualities,
	cts *containers.Containers,
) error {
	for _, p := range ps.allFromMap() {
		policyID := uint(p.ID)

		// NOTE: Equal has precedence over NotEqual, so NotEqual must be updated first

		// UIDFilters
		uidEqualities := p.UIDFilter.Equalities()
		updateEqualities(fEqs.uidEqualities, uidEqualities.NotEqual, notEqual, policyID)
		updateEqualities(fEqs.uidEqualities, uidEqualities.Equal, equal, policyID)

		// PIDFilters
		pidEqualities := p.PIDFilter.Equalities()
		updateEqualities(fEqs.pidEqualities, pidEqualities.NotEqual, notEqual, policyID)
		updateEqualities(fEqs.pidEqualities, pidEqualities.Equal, equal, policyID)

		// MntNSFilters
		mntNSEqualities := p.MntNSFilter.Equalities()
		updateEqualities(fEqs.mntNSEqualities, mntNSEqualities.NotEqual, notEqual, policyID)
		updateEqualities(fEqs.mntNSEqualities, mntNSEqualities.Equal, equal, policyID)

		// PidNSFilters
		pidNSEqualities := p.PidNSFilter.Equalities()
		updateEqualities(fEqs.pidNSEqualities, pidNSEqualities.NotEqual, notEqual, policyID)
		updateEqualities(fEqs.pidNSEqualities, pidNSEqualities.Equal, equal, policyID)

		// ContIDFilters
		contIDEqualities := p.ContIDFilter.Equalities()
		for contID := range contIDEqualities.NotEqual {
			cgroupIDs, err := cts.FindContainerCgroupID32LSB(contID)
			if err != nil {
				return err
			}

			eq := fEqs.cgroupIdEqualities[uint64(cgroupIDs[0])]
			notEqualUpdate(&eq, policyID)
			fEqs.cgroupIdEqualities[uint64(cgroupIDs[0])] = eq
		}
		for contID := range contIDEqualities.Equal {
			cgroupIDs, err := cts.FindContainerCgroupID32LSB(contID)
			if err != nil {
				return err
			}

			eq := fEqs.cgroupIdEqualities[uint64(cgroupIDs[0])]
			equalUpdate(&eq, policyID)
			fEqs.cgroupIdEqualities[uint64(cgroupIDs[0])] = eq
		}

		// UTSFilters
		utsEqualities := p.UTSFilter.Equalities()
		updateEqualities(fEqs.utsEqualities, utsEqualities.NotEqual, notEqual, policyID)
		updateEqualities(fEqs.utsEqualities, utsEqualities.Equal, equal, policyID)

		// CommFilters
		commEqualities := p.CommFilter.Equalities()
		updateEqualities(fEqs.commEqualities, commEqualities.NotEqual, notEqual, policyID)
		updateEqualities(fEqs.commEqualities, commEqualities.Equal, equal, policyID)

		// DataFilters
		dataEqualities := p.DataFilter.Equalities()
		updateEqualities(fEqs.dataEqualitiesExactly, dataEqualities.NotEqual, notEqual, policyID)
		updateEqualities(fEqs.dataEqualitiesExactly, dataEqualities.Equal, equal, policyID)

		updateAffixEqualities(fEqs.dataEqualitiesPrefix, dataEqualities.NotEqualPrefix, notEqual, policyID)
		updateAffixEqualities(fEqs.dataEqualitiesPrefix, dataEqualities.EqualPrefix, equal, policyID)

		updateAffixEqualities(fEqs.dataEqualitiesSuffix, dataEqualities.NotEqualSuffix, notEqual, policyID)
		updateAffixEqualities(fEqs.dataEqualitiesSuffix, dataEqualities.EqualSuffix, equal, policyID)

		// BinaryFilters
		binaryEqualities := p.BinaryFilter.Equalities()
		updateEqualities(fEqs.binaryEqualities, binaryEqualities.NotEqual, notEqual, policyID)
		updateEqualities(fEqs.binaryEqualities, binaryEqualities.Equal, equal, policyID)
	}

	return nil
}

// computeProcTreeEqualities computes the equalities for the process tree filter
// in the policies updating the provided eqs map.
func (ps *policies) computeProcTreeEqualities(eqs map[uint32]equality) {
	for _, p := range ps.allFromMap() {
		policyID := uint(p.ID)

		procTreeEqualities := p.ProcessTreeFilter.Equalities()
		updateEqualities(eqs, procTreeEqualities.NotEqual, notEqual, policyID)
		updateEqualities(eqs, procTreeEqualities.Equal, equal, policyID)
	}
}
