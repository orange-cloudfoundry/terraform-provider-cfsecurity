package cfsecurity

import (
	"errors"
	"net/http"
	"reflect"

	"github.com/orange-cloudfoundry/cf-security-entitlement/v2/client"
)

func getListBindChanges(old []bind, new []bind) (remove []bind, add []bind) {

	for _, source := range old {
		toDelete := true
		for _, item := range new {
			if source.AsgID == item.AsgID && source.SpaceID == item.SpaceID {
				toDelete = false
				break
			}
		}
		if toDelete {
			remove = append(remove, source)
		}
	}
	for _, source := range new {
		toAdd := true
		for _, item := range old {
			if source.AsgID == item.AsgID && source.SpaceID == item.SpaceID {
				toAdd = false
				break
			}
		}
		if toAdd {
			add = append(add, source)
		}
	}

	return remove, add
}

// intersectSlices return the intersection of 2 slices ([1, 1, 3, 4, 5, 6] & [2, 3, 6] >> [3, 6])
// sources and items must be an array of whatever and element type can be whatever and can be different
// match function must return true if item and source given match
func intersectSlices(sources interface{}, items interface{}, match func(source, item interface{}) bool) []interface{} {
	sourceValue := reflect.ValueOf(sources)
	itemsValue := reflect.ValueOf(items)
	final := make([]interface{}, 0)
	for i := 0; i < sourceValue.Len(); i++ {
		inside := false
		src := sourceValue.Index(i).Interface()
		for p := 0; p < itemsValue.Len(); p++ {
			item := itemsValue.Index(p).Interface()
			if match(src, item) {
				inside = true
				break
			}
		}
		if inside {
			final = append(final, src)
		}
	}
	return final
}

// isInSlice Try to find in a list of whatever an element
func isInSlice(objects interface{}, match func(object interface{}) bool) bool {
	objectsValue := reflect.ValueOf(objects)
	for i := 0; i < objectsValue.Len(); i++ {
		object := objectsValue.Index(i).Interface()
		if match(object) {
			return true
		}
	}
	return false
}

func isNotFoundErr(err error) bool {
	var httpErr client.CloudFoundryHTTPError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode == http.StatusNotFound
	}
	return false
}
