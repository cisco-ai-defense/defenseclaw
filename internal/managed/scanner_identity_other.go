//go:build !windows

package managed

// RequireWindowsGatewayPathOutsideUserProfiles applies only to the Windows
// LocalSystem gateway service.
func RequireWindowsGatewayPathOutsideUserProfiles(string) error { return nil }
