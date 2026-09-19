package app

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/fatih/color"
)

type Colorizer struct {
	enabled bool

	logError *color.Color
	logInfo  *color.Color
	logDebug *color.Color
	logTrace *color.Color

	title             *color.Color
	statusSuccess     *color.Color
	statusRedirect    *color.Color
	statusClientError *color.Color
	statusServerError *color.Color
	header            *color.Color
	meta              *color.Color
}

func NewColorizer(enabled bool) *Colorizer {
	c := &Colorizer{enabled: enabled}
	c.logError = color.New(color.FgRed, color.Bold)
	c.logInfo = color.New(color.FgGreen, color.Bold)
	c.logDebug = color.New(color.FgYellow, color.Bold)
	c.logTrace = color.New(color.FgHiBlack, color.Bold)
	c.title = color.New(color.FgCyan, color.Bold)
	c.statusSuccess = color.New(color.FgGreen, color.Bold)
	c.statusRedirect = color.New(color.FgCyan, color.Bold)
	c.statusClientError = color.New(color.FgYellow, color.Bold)
	c.statusServerError = color.New(color.FgRed, color.Bold)
	c.header = color.New(color.FgBlue, color.Bold)
	c.meta = color.New(color.FgMagenta)
	for _, clr := range c.allColors() {
		if enabled {
			clr.EnableColor()
		} else {
			clr.DisableColor()
		}
	}
	return c
}

func (c *Colorizer) allColors() []*color.Color {
	return []*color.Color{
		c.logError,
		c.logInfo,
		c.logDebug,
		c.logTrace,
		c.title,
		c.statusSuccess,
		c.statusRedirect,
		c.statusClientError,
		c.statusServerError,
		c.header,
		c.meta,
	}
}

func (c *Colorizer) sprintf(clr *color.Color, format string, args ...any) string {
	if c == nil || !c.enabled || clr == nil {
		return fmt.Sprintf(format, args...)
	}
	return clr.Sprintf(format, args...)
}

func (c *Colorizer) Title(format string, args ...any) string {
	return c.sprintf(c.title, format, args...)
}
func (c *Colorizer) Header(format string, args ...any) string {
	return c.sprintf(c.header, format, args...)
}
func (c *Colorizer) Meta(format string, args ...any) string {
	return c.sprintf(c.meta, format, args...)
}

func (c *Colorizer) Status(status string, code int) string {
	switch {
	case code >= 500:
		return c.sprintf(c.statusServerError, "%s", status)
	case code >= 400:
		return c.sprintf(c.statusClientError, "%s", status)
	case code >= 300:
		return c.sprintf(c.statusRedirect, "%s", status)
	default:
		return c.sprintf(c.statusSuccess, "%s", status)
	}
}

func (c *Colorizer) LogLabel(level LogLevel) string {
	switch level {
	case LogLevelError:
		return c.sprintf(c.logError, "%s", levelName(level))
	case LogLevelInfo:
		return c.sprintf(c.logInfo, "%s", levelName(level))
	case LogLevelDebug:
		return c.sprintf(c.logDebug, "%s", levelName(level))
	case LogLevelTrace:
		return c.sprintf(c.logTrace, "%s", levelName(level))
	default:
		return levelName(level)
	}
}

func formatHeaderLine(colorizer *Colorizer, key string, values []string) string {
	label := key
	if colorizer != nil {
		label = colorizer.Header("%s", key)
	}
	if len(values) == 0 {
		return fmt.Sprintf("%s:", label)
	}
	return fmt.Sprintf("%s: %s", label, values[0]) + joinExtraValues(values[1:])
}

func joinExtraValues(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return ", " + strings.Join(values, ", ")
}

func formatResponseStatus(colorizer *Colorizer, resp *http.Response) string {
	if resp == nil {
		return ""
	}
	if colorizer == nil {
		return resp.Status
	}
	return colorizer.Status(resp.Status, resp.StatusCode)
}
