package main

import (
	"reflect"
	"testing"
	"time"
)

func TestGetScanDuration(t *testing.T) {
	first := time.Now()
	second := first.AddDate(0, 0, 1)
	ans := time.Date(first.Year(), first.Month(), first.Day(), 0, 0, 0, 0, time.Local)

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

			name: "If the days are the same, the date will be returned as 'to' plus one day",
			args: args{
				from: first,
				to:   first,
			},
			want: &scanDuration{
				From: ans,
				To:   ans.AddDate(0, 0, 1),
			},
		},
		{

			name: "If 'to' is not exactly 0:00 am, the date will be returned as 'to' plus one day",
			args: args{
				from: first,
				to:   second,
			},
			want: &scanDuration{
				From: ans,
				To:   ans.AddDate(0, 0, 2),
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
