package pyxis

import (
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	pyxisAPI = "https://catalog.redhat.com/api/containers/v1/images/nvr/%s" +
		"?filter=parsed_data.labels=em=(name=='architecture'andvalue=='%s')"
)

type pyxis struct {
	Data []struct {
		ContentSets []string `json:"content_sets"`
	} `json:"data"`
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
	Total    int `json:"total"`
}

func FetchContentSets(nvr, arch string) []string {
	url := fmt.Sprintf(pyxisAPI, nvr, arch)
	resp, err := http.Get(url)
	fmt.Println(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var res pyxis
	if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil
	}

	if len(res.Data) != 1 {
		return nil
	}

	return res.Data[0].ContentSets
}
