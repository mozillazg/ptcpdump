package orderedmap

import "container/list"

type orderedMapElement struct {
	key, value interface{}
}

type OrderedMap struct {
	kv map[interface{}]*list.Element
	ll *list.List
}

func NewOrderedMap() *OrderedMap {
	return &OrderedMap{
		kv: make(map[interface{}]*list.Element),
		ll: list.New(),
	}
}

// Get returns the value for a key. If the key does not exist, the second return
// parameter will be false and the value will be nil.
func (m *OrderedMap) Get(key interface{}) (interface{}, bool) {
	value, ok := m.kv[key]
	if ok {
		return value.Value.(*orderedMapElement).value, true
	}

	return nil, false
}

// Set will set (or replace) a value for a key. If the key was new, then true
// will be returned. The returned value will be false if the value was replaced
// (even if the value was the same).
func (m *OrderedMap) Set(key, value interface{}) bool {
	_, didExist := m.kv[key]

	if !didExist {
		element := m.ll.PushBack(&orderedMapElement{key, value})
		m.kv[key] = element
	} else {
		m.kv[key].Value.(*orderedMapElement).value = value
	}

	return !didExist
}

// GetOrDefault returns the value for a key. If the key does not exist, returns
// the default value instead.
func (m *OrderedMap) GetOrDefault(key, defaultValue interface{}) interface{} {
	if value, ok := m.kv[key]; ok {
		return value.Value.(*orderedMapElement).value
	}

	return defaultValue
}

// GetElement returns the element for a key. If the key does not exist, the
// pointer will be nil.
func (m *OrderedMap) GetElement(key interface{}) *Element {
	value, ok := m.kv[key]
	if ok {
		element := value.Value.(*orderedMapElement)
		return &Element{
			element: value,
			Key:     element.key,
			Value:   element.value,
		}
	}

	return nil
}

// Len returns the number of elements in the map.
func (m *OrderedMap) Len() int {
	return len(m.kv)
}

// Keys returns all of the keys in the order they were inserted. If a key was
// replaced it will retain the same position. To ensure most recently set keys
// are always at the end you must always Delete before Set.
func (m *OrderedMap) Keys() (keys []interface{}) {
	keys = make([]interface{}, m.Len())

	element := m.ll.Front()
	for i := 0; element != nil; i++ {
		keys[i] = element.Value.(*orderedMapElement).key
		element = element.Next()
	}

	return keys
}

// Delete will remove a key from the map. It will return true if the key was
// removed (the key did exist).
func (m *OrderedMap) Delete(key interface{}) (didDelete bool) {
	element, ok := m.kv[key]
	if ok {
		m.ll.Remove(element)
		delete(m.kv, key)
	}

	return ok
}

// Front will return the element that is the first (oldest Set element). If
// there are no elements this will return nil.
func (m *OrderedMap) Front() *Element {
	front := m.ll.Front()
	if front == nil {
		return nil
	}

	element := front.Value.(*orderedMapElement)

	return &Element{
		element: front,
		Key:     element.key,
		Value:   element.value,
	}
}

// Back will return the element that is the last (most recent Set element). If
// there are no elements this will return nil.
func (m *OrderedMap) Back() *Element {
	back := m.ll.Back()
	if back == nil {
		return nil
	}

	element := back.Value.(*orderedMapElement)

	return &Element{
		element: back,
		Key:     element.key,
		Value:   element.value,
	}
}

// Copy returns a new OrderedMap with the same elements.
// Using Copy while there are concurrent writes may mangle the result.
func (m *OrderedMap) Copy() *OrderedMap {
	m2 := NewOrderedMap()

	for el := m.Front(); el != nil; el = el.Next() {
		m2.Set(el.Key, el.Value)
	}

	return m2
}
