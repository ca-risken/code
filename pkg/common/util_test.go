package common

import (
	"os"
	"reflect"
	"testing"

	"github.com/google/go-github/v44/github"
)

func TestFilterByNamePattern(t *testing.T) {
	type args struct {
		repos   []*github.Repository
		pattern string
	}
	tests := []struct {
		name string
		args args
		want []*github.Repository
	}{
		{
			name: "Return repositories contained risken in repository name",
			args: args{
				repos: []*github.Repository{
					{
						Name: github.String("risken-core"),
					},
					{
						Name: github.String("core"),
					},
				},
				pattern: "risken",
			},
			want: []*github.Repository{
				{
					Name: github.String("risken-core"),
				},
			},
		},
		{
			name: "Return all repositories",
			args: args{
				repos: []*github.Repository{
					{
						Name: github.String("risken-core"),
					},
					{
						Name: github.String("core"),
					},
				},
				pattern: "",
			},
			want: []*github.Repository{
				{
					Name: github.String("risken-core"),
				},
				{
					Name: github.String("core"),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FilterByNamePattern(tt.args.repos, tt.args.pattern); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("filterByNamePattern() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterByVisibility(t *testing.T) {
	visibilityPublic := "public"
	visibilityInternal := "internal"
	visibilityPrivate := "private"
	type args struct {
		repos        []*github.Repository
		scanPublic   bool
		scanInternal bool
		scanPrivate  bool
	}
	tests := []struct {
		name string
		args args
		want []*github.Repository
	}{
		{
			name: "Return public repositories",
			args: args{
				repos: []*github.Repository{
					{
						Name:       github.String("public-repo"),
						Visibility: &visibilityPublic,
					},
					{
						Name:       github.String("internal-repo"),
						Visibility: &visibilityInternal,
					},
					{
						Name:       github.String("private-repo"),
						Visibility: &visibilityPrivate,
					},
				},
				scanPublic: true,
			},
			want: []*github.Repository{
				{
					Name:       github.String("public-repo"),
					Visibility: &visibilityPublic,
				},
			},
		},
		{
			name: "Return internal repositories",
			args: args{
				repos: []*github.Repository{
					{
						Name:       github.String("public-repo"),
						Visibility: &visibilityPublic,
					},
					{
						Name:       github.String("internal-repo"),
						Visibility: &visibilityInternal,
					},
					{
						Name:       github.String("private-repo"),
						Visibility: &visibilityPrivate,
					},
				},
				scanInternal: true,
			},
			want: []*github.Repository{
				{
					Name:       github.String("internal-repo"),
					Visibility: &visibilityInternal,
				},
			},
		},
		{
			name: "Return private repositories",
			args: args{
				repos: []*github.Repository{
					{
						Name:       github.String("public-repo"),
						Visibility: &visibilityPublic,
					},
					{
						Name:       github.String("internal-repo"),
						Visibility: &visibilityInternal,
					},
					{
						Name:       github.String("private-repo"),
						Visibility: &visibilityPrivate,
					},
				},
				scanPrivate: true,
			},
			want: []*github.Repository{
				{
					Name:       github.String("private-repo"),
					Visibility: &visibilityPrivate,
				},
			},
		},
		{
			name: "Return all repositories",
			args: args{
				repos: []*github.Repository{
					{
						Name:       github.String("public-repo"),
						Visibility: &visibilityPublic,
					},
					{
						Name:       github.String("internal-repo"),
						Visibility: &visibilityInternal,
					},
					{
						Name:       github.String("private-repo"),
						Visibility: &visibilityPrivate,
					},
				},
				scanPublic:   true,
				scanInternal: true,
				scanPrivate:  true,
			},
			want: []*github.Repository{
				{
					Name:       github.String("public-repo"),
					Visibility: &visibilityPublic,
				},
				{
					Name:       github.String("internal-repo"),
					Visibility: &visibilityInternal,
				},
				{
					Name:       github.String("private-repo"),
					Visibility: &visibilityPrivate,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FilterByVisibility(tt.args.repos, tt.args.scanPublic, tt.args.scanInternal, tt.args.scanPrivate); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("filterByRepository() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCutString(t *testing.T) {
	type args struct {
		input string
		cut   int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Short string, no cut needed",
			args: args{
				input: "Hello",
				cut:   10,
			},
			want: "Hello",
		},
		{
			name: "Exact cut length",
			args: args{
				input: "Hello, World!",
				cut:   5,
			},
			want: "Hello ...",
		},
		{
			name: "Long string, cut applied",
			args: args{
				input: "This is a long string that needs to be cut",
				cut:   10,
			},
			want: "This is a  ...",
		},
		{
			name: "Empty string",
			args: args{
				input: "",
				cut:   5,
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CutString(tt.args.input, tt.args.cut); got != tt.want {
				t.Errorf("CutString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateCloneDir(t *testing.T) {
	type args struct {
		repoName string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Valid repo name",
			args: args{
				repoName: "testRepo",
			},
			wantErr: false,
		},
		{
			name: "Empty repo name",
			args: args{
				repoName: "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, err := CreateCloneDir(tt.args.repoName)
			if err == nil && tt.wantErr {
				t.Errorf("CreateCloneDir() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && !tt.wantErr {
				t.Errorf("CreateCloneDir() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil {
				os.RemoveAll(dir)
			}
		})
	}
}
