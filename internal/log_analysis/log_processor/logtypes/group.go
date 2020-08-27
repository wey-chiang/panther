package logtypes

import (
	"fmt"
	"github.com/pkg/errors"
)

type Finder interface {
	Find(logType string) Entry
}

type Group interface {
	Finder
	Len() int
	Entries() []Entry
}

func AppendFind(entries []Entry, finder Finder, names ...string) []Entry {
	for _, name := range names {
		if entry := finder.Find(name); entry != nil {
			entries = append(entries, entry)
		}
	}
	return entries
}

type group struct {
	entries map[string]Entry
}

var _ Finder = (*group)(nil)

func MustFind(f Finder, name string) Entry {
	if entry := f.Find(name); entry != nil {
		return entry
	}
	panic(fmt.Sprintf(`entry %q not found`, name))
}

func MustMerge(groups ...Group) Group {
	merged, err := Merge(groups...)
	if err != nil {
		panic(err)
	}
	return merged
}

func Merge(groups ...Group) (Group, error) {
	merged := group{
		entries: map[string]Entry{},
	}
	for _, g := range groups {
		for _, e := range g.Entries() {
			name := e.String()
			if _, duplicate := merged.entries[name]; duplicate {
				return nil, errors.Errorf(`duplicate entry %q`, name)
			}
			merged.entries[name] = e
		}
	}
	return &merged, nil
}

func MustBuildGroup(entries ...EntryBuilder) Group {
	index, err := BuildGroup(entries...)
	if err != nil {
		panic(err)
	}
	return index
}

func BuildGroup(entries ...EntryBuilder) (Group, error) {
	index := group{
		entries: make(map[string]Entry, len(entries)),
	}
	for _, b := range entries {
		entry, err := b.BuildEntry()
		if err != nil {
			return nil, err
		}
		name := entry.String()
		if _, duplicate := index.entries[name]; duplicate {
			return nil, errors.Errorf("duplicate log entry %q", name)
		}
		index.entries[name] = entry
	}
	return &index, nil
}

func (i *group) Find(name string) Entry {
	return i.entries[name]
}

func (i *group) Entries() (entries []Entry) {
	for _, entry := range i.entries {
		entries = append(entries, entry)
	}
	return entries
}

func (i *group) Len() int {
	return len(i.entries)
}
