package main

import (
	"runtime/debug"
	"testing"
)

func TestResolveVersion(t *testing.T) {
	vcsInfo := &debug.BuildInfo{Settings: []debug.BuildSetting{
		{Key: "vcs.revision", Value: "0123456789abcdef"},
		{Key: "vcs.modified", Value: "true"},
	}}

	cases := []struct {
		name    string
		stamped string
		info    *debug.BuildInfo
		want    string
	}{
		{name: "release stamp wins", stamped: "v0.5.0", info: vcsInfo, want: "v0.5.0"},
		{name: "dev build", stamped: "dev", info: vcsInfo, want: "dev-0123456"},
		{name: "no build info", stamped: "dev", info: nil, want: "dev"},
		{name: "no vcs settings", stamped: "dev", info: &debug.BuildInfo{}, want: "dev"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveVersion(tc.stamped, tc.info); got != tc.want {
				t.Fatalf("resolveVersion(%q) = %q, want %q", tc.stamped, got, tc.want)
			}
		})
	}
}
