# 🔃 github.com/elliotchance/orderedmap [![GoDoc](https://godoc.org/github.com/elliotchance/orderedmap?status.svg)](https://godoc.org/github.com/elliotchance/orderedmap) [![Build Status](https://travis-ci.org/elliotchance/orderedmap.svg?branch=master)](https://travis-ci.org/elliotchance/orderedmap)

## Installation

```bash
go get -u github.com/elliotchance/orderedmap
```

## Basic Usage

An `*OrderedMap` is a high performance ordered map that maintains amortized O(1)
for `Set`, `Get`, `Delete` and `Len`:

```go
m := orderedmap.NewOrderedMap()

m.Set("foo", "bar")
m.Set("qux", 1.23)
m.Set(123, true)

m.Delete("qux")
```

Internally an `*OrderedMap` uses a combination of a map and linked list.

## Iterating

Be careful using `Keys()` as it will create a copy of all of the keys so it's
only suitable for a small number of items:

```go
for _, key := range m.Keys() {
	value, _:= m.Get(key)
	fmt.Println(key, value)
}
```

For larger maps you should use `Front()` or `Back()` to iterate per element:

```go
// Iterate through all elements from oldest to newest:
for el := m.Front(); el != nil; el = el.Next() {
    fmt.Println(el.Key, el.Value)
}

// You can also use Back and Prev to iterate in reverse:
for el := m.Back(); el != nil; el = el.Prev() {
    fmt.Println(el.Key, el.Value)
}
```

The iterator is safe to use bidirectionally, and will return `nil` once it goes
beyond the first or last item.

If the map is changing while the iteration is in-flight it may produce
unexpected behavior.

## Performance

CPU: Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz

RAM: 8GB

System: Windows 10

```shell
$go test -benchmem -run=^$ github.com/elliotchance/orderedmap -bench BenchmarkAll
```

map[int]bool

|         | map                 | orderedmap          |
| ------- | ------------------- | ------------------- |
| set     | 198 ns/op, 44 B/op  | 722 ns/op, 211 B/op |
| get     | 18 ns/op, 0 B/op    | 37.3 ns/op, 0 B/op  |
| delete  | 888 ns/op, 211 B/op | 280 ns/op, 44 B/op  |
| Iterate | 206 ns/op, 44 B/op  | 693 ns/op, 259 B/op |

map[string]bool(PS : Use strconv.Itoa())

|             | map                 | orderedmap              |
| ----------- | ------------------- | ----------------------- |
| set         | 421 ns/op, 86 B/op  | 1048 ns/op, 243 B/op    |
| get         | 81.1 ns/op, 2 B/op  | 97.8 ns/op, 2 B/op      |
| delete      | 737 ns/op, 122 B/op | 1188 ns/op, 251 B/op    |
| Iterate all | 14706 ns/op, 1 B/op | 52671 ns/op, 16391 B/op |

Big map[int]bool (10000000 keys)

|             | map                              | orderedmap                      |
| ----------- | -------------------------------- | ------------------------------- |
| set all     | 1.834559 s/op, 423.9470291 MB/op | 7.5564667 s/op, 1784.1483 MB/op |
| get all     | 2.6367878 s/op, 423.9698 MB/op   | 9.0232475 s/op, 1784.1086 MB/op |
| Iterate all | 1.9526784 s/op, 423.9042 MB/op   | 8.2495265 s/op, 1936.7619 MB/op |

Big map[string]bool (10000000 keys)

|             | map                               | orderedmap                          |
| ----------- | --------------------------------- | ----------------------------------- |
| set all     | 4.8893923 s/op, 921.33435 MB/op   | 10.4405527 s/op, 2089.0144 MB/op    |
| get all     | 7.122791 s/op, 997.3802643 MB/op  | 13.2613692 s/op, 2165.09521 MB/op   |
| Iterate all | 5.1688922 s/op, 921.4619293 MB/op | 12.6623711 s/op, 2241.5272064 MB/op |
