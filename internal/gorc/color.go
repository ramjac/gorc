package gorc

import (
	"fmt"
	"net/http"

	"github.com/fatih/color"
)

type Colorizer struct {
	enabled bool

	logError *color.Color
	logInfo  *color.Color
	logDebug *color.Color
	logTrace *color.Color

	title   *color.Color
	status2 *color.Color
	status3 *color.Color
	status4 *color.Color
	status5 *color.Color
	header  *color.Color
	meta    *color.Color
}

func NewColorizer(enabled bool) *Colorizer {
	c := &Colorizer{enabled: enabled}
	c.logError = color.New(color.FgRed, color.Bold)
	c.logInfo = color.New(color.FgGreen, color.Bold)
	c.logDebug = color.New(color.FgYellow, color.Bold)
	c.logTrace = color.New(color.FgHiBlack, color.Bold)
	c.title = color.New(color.FgCyan, color.Bold)
	c.status2 = color.New(color.FgGreen, color.Bold)
	c.status3 = color.New(color.FgCyan, color.Bold)
	c.status4 = color.New(color.FgYellow, color.Bold)
	c.status5 = color.New(color.FgRed, color.Bold)
	c.header = color.New(color.FgBlue, color.Bold)
	c.meta = color.New(color.FgMagenta)
	for _, clr := range []*color.Color{c.logError, c.logInfo, c.logDebug, c.logTrace, c.title, c.status2, c.status3, c.status4, c.status5, c.header, c.meta} {
		if enabled {
			clr.EnableColor()
		} else {
			clr.DisableColor()
		}
	}
	return c
}

func (c *Colorizer) Sprintf(clr *color.Color, format string, args ...any) string {
	if c == nil || !c.enabled || clr == nil {
		return fmt.Sprintf(format, args...)
	}
	return clr.Sprintf(format, args...)
}

func (c *Colorizer) Title(format string, args ...any) string  { return c.Sprintf(c.title, format, args...) }
func (c *Colorizer) Header(format string, args ...any) string { return c.Sprintf(c.header, format, args...) }
func (c *Colorizer) Meta(format string, args ...any) string   { return c.Sprintf(c.meta, format, args...) }

func (c *Colorizer) Status(status string, code int) string {
	switch {
	case code >= 500:
		return c.Sprintf(c.status5, "%s", status)
	case code >= 400:
		return c.Sprintf(c.status4, "%s", status)
	case code >= 300:
		return c.Sprintf(c.status3, "%s", status)
	default:
		return c.Sprintf(c.status2, "%s", status)
	}
}

func (c *Colorizer) LogLabel(level LogLevel) string {
	switch level {
	case LogLevelError:
		return c.Sprintf(c.logError, "%s", levelName(level))
	case LogLevelInfo:
		return c.Sprintf(c.logInfo, "%s", levelName(level))
	case LogLevelDebug:
		return c.Sprintf(c.logDebug, "%s", levelName(level))
	case LogLevelTrace:
		return c.Sprintf(c.logTrace, "%s", levelName(level))
	default:
		return levelName(level)
	}
}

func shouldEnableColor(noColor bool) bool {
	return !noColor
}

func formatHeaderLine(colorizer *Colorizer, key string, values []string) string {
	return fmt.Sprintf("%s: %s", colorizer.Header("%s", key), values[0]) + joinExtraValues(values[1:])
}

func joinExtraValues(values []string) string {
	if len(values) == 0 {
		return ""
	}
	line := ""
	for _, value := range values {
		line += ", " + value
	}
	return line
}

func formatResponseStatus(colorizer *Colorizer, resp *http.Response) string {
	if resp == nil {
		return ""
	}
	return colorizer.Status(resp.Status, resp.StatusCode)
}
