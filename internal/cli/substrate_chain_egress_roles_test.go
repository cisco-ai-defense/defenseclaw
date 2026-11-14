package cli

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

// TestSubstrateChainEgressActionGatewayAndLeaderAgree pins GAP-0252: the
// gateway role (the actor hook disposition) and the leader role (the egress
// callout) must take substrate.chain_egress_action from the same rendered
// ConfigMap and resolve it to the same action. It reads every committed chart
// render (tests/golden, kept current by TestChartGoldens): both Deployments
// mount the one defenseclaw-config ConfigMap at the path DEFENSECLAW_CONFIG
// names, neither passes the removed --chain-egress-action flag (GAP-0253), and the
// role's own wiring (gatewayRoleChainEgressAction, leaderChainEgressAction,
// the functions the serve paths call) gives the same action, equal to the
// value written in that config.yaml.
func TestSubstrateChainEgressActionGatewayAndLeaderAgree(t *testing.T) {
	goldens, err := filepath.Glob(filepath.Join("..", "..", "deploy", "helm", "defenseclaw-substrate", "tests", "golden", "*.yaml"))
	if err != nil || len(goldens) == 0 {
		t.Fatalf("no chart goldens found: %v", err)
	}
	sawAlert := false
	for _, golden := range goldens {
		t.Run(filepath.Base(golden), func(t *testing.T) {
			r := readChartRender(t, golden)
			if r.configYAML == "" {
				t.Skip("this render has no defenseclaw-config ConfigMap")
			}
			gw, ok := r.roles["gateway"]
			if !ok {
				t.Skip("this render has no gateway role")
			}
			leader, ok := r.roles["leader"]
			if !ok {
				t.Fatalf("the gateway role renders without a leader role")
			}
			for name, role := range map[string]chartRole{"gateway": gw, "leader": leader} {
				if role.configMap != "defenseclaw-config" {
					t.Fatalf("%s reads DEFENSECLAW_CONFIG=%q from ConfigMap %q, want defenseclaw-config", name, role.configPath, role.configMap)
				}
				if role.chainFlag != "" {
					t.Fatalf("%s passes --chain-egress-action=%q; the chart must leave it to config substrate.chain_egress_action", name, role.chainFlag)
				}
			}
			// The roles read the substrate section of this one file. Decode it
			// with the config package's own type for every render; where the
			// strict loader can run here (managed renders need a root-owned
			// file, the managed trust check), it must read the same value.
			var doc struct {
				Substrate config.SubstrateConfig `yaml:"substrate"`
			}
			if err := yaml.Unmarshal([]byte(r.configYAML), &doc); err != nil {
				t.Fatalf("decode the rendered config.yaml: %v", err)
			}
			cfg := &config.Config{Substrate: doc.Substrate}
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(path, []byte(r.configYAML), 0o600); err != nil {
				t.Fatal(err)
			}
			if strict, err := config.LoadFromFile(path); err == nil {
				if got, want := strict.Substrate.ChainEgressAction, doc.Substrate.ChainEgressAction; got != want {
					t.Fatalf("the strict loader reads chain_egress_action %q, the substrate section says %q", got, want)
				}
			} else if !strings.Contains(err.Error(), "managed_enterprise config trust check failed") {
				t.Fatalf("load the rendered config.yaml: %v", err)
			}
			// Each role's own wiring (the functions the serve paths call), not
			// the shared resolver: a role that hard-codes or reads another
			// source fails here.
			gwAction, gwSource := gatewayRoleChainEgressAction(cfg)
			leaderAction, leaderSource := leaderChainEgressAction(cfg)
			if gwAction != leaderAction || gwSource != leaderSource {
				t.Fatalf("gateway role %s (%s), leader %s (%s): the roles disagree", gwAction, gwSource, leaderAction, leaderSource)
			}
			// The expected value comes from the rendered text itself, not from
			// the resolver: block when the key is absent or empty.
			want := strings.ToLower(strings.TrimSpace(doc.Substrate.ChainEgressAction))
			if want == "" {
				want = config.SubstrateChainEgressBlock
			}
			if gwAction != want || leaderAction != want {
				t.Fatalf("the rendered config says %s; the gateway role resolves %s, the leader %s", want, gwAction, leaderAction)
			}
			if err := gateway.SetSubstrateChainEgressAction(gwAction); err != nil {
				t.Fatalf("the gateway role refuses the action the leader runs with: %v", err)
			}
			t.Cleanup(func() { _ = gateway.SetSubstrateChainEgressAction("") })
			if gwAction == config.SubstrateChainEgressAlert {
				sawAlert = true
			}
		})
	}
	if !sawAlert {
		t.Fatalf("no chart golden sets chain_egress_action: alert, so the non-default value is not covered")
	}
}

type chartRole struct {
	configPath, configMap, chainFlag string
}

type chartRender struct {
	configYAML string
	roles      map[string]chartRole
}

// readChartRender reads the defenseclaw-config config.yaml and, for each
// container started with --substrate-role, the ConfigMap that holds the
// file DEFENSECLAW_CONFIG names (a directory mount, or a single-file mount
// at that path as in managed mode) and any --chain-egress-action flag.
func readChartRender(t *testing.T, path string) chartRender {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := chartRender{roles: map[string]chartRole{}}
	dec := yaml.NewDecoder(f)
	for {
		var doc struct {
			Kind     string                `yaml:"kind"`
			Metadata struct{ Name string } `yaml:"metadata"`
			Data     map[string]string     `yaml:"data"`
			Spec     struct {
				Template struct {
					Spec struct {
						Containers []struct {
							Args         []string                       `yaml:"args"`
							Env          []struct{ Name, Value string } `yaml:"env"`
							VolumeMounts []struct {
								Name      string `yaml:"name"`
								MountPath string `yaml:"mountPath"`
							} `yaml:"volumeMounts"`
						} `yaml:"containers"`
						Volumes []struct {
							Name      string `yaml:"name"`
							ConfigMap *struct {
								Name string `yaml:"name"`
							} `yaml:"configMap"`
						} `yaml:"volumes"`
					} `yaml:"spec"`
				} `yaml:"template"`
			} `yaml:"spec"`
		}
		if err := dec.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("%s: %v", path, err)
		}
		if doc.Kind == "ConfigMap" && doc.Metadata.Name == "defenseclaw-config" {
			out.configYAML = doc.Data["config.yaml"]
		}
		if doc.Kind != "Deployment" {
			continue
		}
		pod := doc.Spec.Template.Spec
		for _, c := range pod.Containers {
			role := flagValue(c.Args, "--substrate-role")
			if role == "" {
				continue
			}
			r := chartRole{chainFlag: flagValue(c.Args, "--chain-egress-action")}
			for _, e := range c.Env {
				if e.Name == "DEFENSECLAW_CONFIG" {
					r.configPath = e.Value
				}
			}
			for _, m := range c.VolumeMounts {
				if r.configPath == "" || (m.MountPath != r.configPath && !strings.HasPrefix(r.configPath, strings.TrimSuffix(m.MountPath, "/")+"/")) {
					continue
				}
				for _, v := range pod.Volumes {
					if v.Name == m.Name && v.ConfigMap != nil {
						r.configMap = v.ConfigMap.Name
					}
				}
			}
			out.roles[role] = r
		}
	}
	return out
}

// flagValue returns the value of --name=value or --name value in args.
func flagValue(args []string, name string) string {
	for i, a := range args {
		if v, ok := strings.CutPrefix(a, name+"="); ok {
			return v
		}
		if a == name && i+1 < len(args) && !slices.Contains([]string{"", "--"}, args[i+1]) {
			return args[i+1]
		}
	}
	return ""
}
