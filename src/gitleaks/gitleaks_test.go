package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/google/go-github/v32/github"
)

var client = gitleaksClient{
	defaultToken:          "xxx",
	limitRepositorySizeKb: 3500000,
	seperateScanDays:      90,
}

func TestSkipScan(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name  string
		input *repositoryFinding
		want  bool
	}{
		{
			name: "Not skip",
			input: &repositoryFinding{
				Archived: github.Bool(false), Fork: github.Bool(false), Disabled: github.Bool(false),
				Size:         github.Int(3500000),
				LastScanedAt: now.Add(-1 * time.Hour), PushedAt: &github.Timestamp{now},
			},
			want: false,
		},
		{
			name:  "Skip(nil)",
			input: nil,
			want:  true,
		},
		{
			name: "Skip(Archived)",
			input: &repositoryFinding{
				Archived: github.Bool(true), Fork: github.Bool(false), Disabled: github.Bool(false),
				Size:         github.Int(3500000),
				LastScanedAt: now.Add(-1 * time.Hour), PushedAt: &github.Timestamp{now},
			},
			want: true,
		},
		{
			name: "Skip(Fork)",
			input: &repositoryFinding{
				Archived: github.Bool(false), Fork: github.Bool(true), Disabled: github.Bool(false),
				Size:         github.Int(3500000),
				LastScanedAt: now.Add(-1 * time.Hour), PushedAt: &github.Timestamp{now},
			},
			want: true,
		},
		{
			name: "Skip(Disabled)",
			input: &repositoryFinding{
				Archived: github.Bool(false), Fork: github.Bool(false), Disabled: github.Bool(true),
				Size:         github.Int(3500000),
				LastScanedAt: now.Add(-1 * time.Hour), PushedAt: &github.Timestamp{now},
			},
			want: true,
		},
		{
			name: "Skip(Size limit)",
			input: &repositoryFinding{
				Archived: github.Bool(false), Fork: github.Bool(false), Disabled: github.Bool(false),
				Size:         github.Int(3500001),
				LastScanedAt: now.Add(-1 * time.Hour), PushedAt: &github.Timestamp{now},
			},
			want: true,
		},
		{
			name: "Skip(already scaned)",
			input: &repositoryFinding{
				Size: github.Int(300000), Archived: github.Bool(false), Fork: github.Bool(false), Disabled: github.Bool(false),
				LastScanedAt: now, PushedAt: &github.Timestamp{now},
			},
			want: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := client.skipScan(c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestGetScanDuration(t *testing.T) {
	first := time.Now()
	second := first.AddDate(0, 0, client.seperateScanDays)
	type durationInput struct {
		CreatedAt      time.Time
		PushedAt       time.Time
		LastScanedAt   time.Time
		CustomScanDays int
	}
	cases := []struct {
		name  string
		input *durationInput
		want  []scanDuration
	}{
		{
			name: "Single duration",
			input: &durationInput{
				CreatedAt: first,
				PushedAt:  first,
			},
			want: []scanDuration{
				{
					From: time.Date(
						first.Year(),
						first.Month(),
						first.Day(),
						0, 0, 0, 0, time.Local),
					To: time.Date(
						first.AddDate(0, 0, client.seperateScanDays).Year(),
						first.AddDate(0, 0, client.seperateScanDays).Month(),
						first.AddDate(0, 0, client.seperateScanDays).Day(),
						0, 0, 0, 0, time.Local),
				},
			},
		},
		{
			name: "Multi durations",
			input: &durationInput{
				CreatedAt: first,
				PushedAt:  first.AddDate(0, 0, client.seperateScanDays+1),
			},
			want: []scanDuration{
				{
					From: time.Date(
						first.Year(),
						first.Month(),
						first.Day(),
						0, 0, 0, 0, time.Local),
					To: time.Date(
						first.AddDate(0, 0, client.seperateScanDays).Year(),
						first.AddDate(0, 0, client.seperateScanDays).Month(),
						first.AddDate(0, 0, client.seperateScanDays).Day(),
						0, 0, 0, 0, time.Local),
				},
				{
					From: time.Date(
						second.Year(),
						second.Month(),
						second.Day(),
						0, 0, 0, 0, time.Local),
					To: time.Date(
						second.AddDate(0, 0, client.seperateScanDays).Year(),
						second.AddDate(0, 0, client.seperateScanDays).Month(),
						second.AddDate(0, 0, client.seperateScanDays).Day(),
						0, 0, 0, 0, time.Local),
				},
			},
		},
		{
			name: "LastScanedAt start",
			input: &durationInput{
				CreatedAt:    first,
				PushedAt:     first.AddDate(0, 0, client.seperateScanDays+1),
				LastScanedAt: first.AddDate(0, 0, client.seperateScanDays),
			},
			want: []scanDuration{
				{
					From: time.Date(
						first.AddDate(0, 0, client.seperateScanDays).Year(),
						first.AddDate(0, 0, client.seperateScanDays).Month(),
						first.AddDate(0, 0, client.seperateScanDays).Day(),
						0, 0, 0, 0, time.Local),
					To: time.Date(
						first.AddDate(0, 0, client.seperateScanDays).AddDate(0, 0, client.seperateScanDays).Year(),
						first.AddDate(0, 0, client.seperateScanDays).AddDate(0, 0, client.seperateScanDays).Month(),
						first.AddDate(0, 0, client.seperateScanDays).AddDate(0, 0, client.seperateScanDays).Day(),
						0, 0, 0, 0, time.Local),
				},
			},
		},
		{
			name: "Unexpected separate days",
			input: &durationInput{
				CreatedAt:      first,
				PushedAt:       first,
				CustomScanDays: -1,
			},
			want: []scanDuration{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.input.CustomScanDays != 0 {
				client.seperateScanDays = c.input.CustomScanDays
			}
			got := client.getScanDuration(c.input.CreatedAt, c.input.PushedAt, c.input.LastScanedAt)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}
