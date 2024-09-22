package orderedmap

import "container/list"

type Element struct {
	Key, Value interface{}

	element *list.Element
}

func newElement(e *list.Element) *Element {
	if e == nil {
		return nil
	}

	element := e.Value.(*orderedMapElement)

	return &Element{
		element: e,
		Key:     element.key,
		Value:   element.value,
	}
}

// Next returns the next element, or nil if it finished.
func (e *Element) Next() *Element {
	return newElement(e.element.Next())
}

// Prev returns the previous element, or nil if it finished.
func (e *Element) Prev() *Element {
	return newElement(e.element.Prev())
}
