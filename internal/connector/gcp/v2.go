package gcp

import (
	"fmt"
	"strings"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
)

func queryScope(options map[string]string) (version, parent, endpoint string, err error) {
	version = connector.FirstNonEmpty(options["api_version"], "v2")
	if version != "v1" && version != "v2" {
		return "", "", "", fmt.Errorf("api_version must be v1 or v2")
	}
	parent = strings.Trim(strings.TrimSpace(options["parent"]), "/")
	parts := strings.Split(parent, "/")
	if len(parts) < 2 || parts[1] == "" || (parts[0] != "organizations" && parts[0] != "folders" && parts[0] != "projects") {
		return "", "", "", fmt.Errorf("parent must start with organizations/ID, folders/ID or projects/ID")
	}
	if len(parts) == 2 {
		parent += "/sources/-"
		parts = strings.Split(parent, "/")
	}
	if (len(parts) != 4 && len(parts) != 6) || parts[2] != "sources" || parts[3] == "" {
		return "", "", "", fmt.Errorf("parent must identify a source, optionally followed by /locations/LOCATION")
	}
	location := strings.TrimSpace(options["location"])
	if len(parts) == 6 {
		if parts[4] != "locations" || parts[5] == "" || (location != "" && location != parts[5]) {
			return "", "", "", fmt.Errorf("parent location and location option must match")
		}
		location = parts[5]
	}
	if version == "v1" && (location != "" || len(parts) == 6) {
		return "", "", "", fmt.Errorf("location requires SCC API v2")
	}
	if strings.Contains(location, "/") || strings.Contains(location, ".") {
		return "", "", "", fmt.Errorf("location must be an SCC location id")
	}
	if version == "v2" {
		location = connector.FirstNonEmpty(location, "global")
		if len(parts) == 4 {
			parent += "/locations/" + location
		}
	}
	endpoint = strings.TrimSpace(options["endpoint"])
	if endpoint == "" && location != "" && location != "global" {
		endpoint = "securitycenter." + location + ".rep.googleapis.com:443"
	}
	return version, parent, endpoint, nil
}
