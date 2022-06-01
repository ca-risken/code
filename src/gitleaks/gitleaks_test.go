package main

import (
	"reflect"
	"testing"
	"time"
)

func TestGetScanDuration(t *testing.T) {
	first := time.Now()
	second := first.AddDate(0, 0, 1)

	type args struct {
		from time.Time
		to   time.Time
	}
	tests := []struct {
		name string
		args args
		want *scanDuration
	}{
		{

			name: "Return scanDuration",
			args: args{
				from: first,
				to:   second,
			},
			want: &scanDuration{
				From: time.Date(first.Year(), first.Month(), first.Day(), 0, 0, 0, 0, time.Local),
				To:   time.Date(second.Year(), second.Month(), second.Day(), 0, 0, 0, 0, time.Local),
			},
		},
		{

			name: "Return nil",
			args: args{
				from: second,
				to:   first,
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getScanDuration(tt.args.from, tt.args.to); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getScanDuration() = %v, want %v", got, tt.want)
			}
		})
	}
}
