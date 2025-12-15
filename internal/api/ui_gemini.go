package api

import (
	"html/template"
	"net/http"

	"github.com/yourorg/llm-proxy-gateway/internal/config"
)

// Super simple "UI": a single page that links to /oauth2/start.
// It expects a gateway user API key to know which tenant to attach the tokens to.
// For local dev, you can paste it into the form.

var geminiTpl = template.Must(template.New("gemini").Parse(`
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Gemini OAuth Login</title>
    <style>
      body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; max-width: 48rem; }
      input, button { font-size: 1rem; padding: .6rem .8rem; }
      .row { display:flex; gap:.5rem; align-items:center; flex-wrap:wrap; }
      code { background:#f3f3f3; padding:.15rem .3rem; border-radius:.25rem; }
      .box { background:#fafafa; border:1px solid #eee; padding:1rem; border-radius:.75rem; }
    </style>
  </head>
  <body>
    <h1>Gemini OAuth (CLI proxy)</h1>
    <div class="box">
      <p>Plak je <b>Gateway API key</b> (voor deze user/tenant). Daarna klik je op <b>Login met Google</b>.</p>
      <form class="row" method="GET" action="/oauth2/start">
        <input style="min-width:28rem" name="gateway_key" placeholder="Gateway API key (Bearer ...)" />
        <button type="submit">Login met Google</button>
      </form>
      <p style="margin-top:1rem">
        Redirect URL (in Google Cloud OAuth): <code>{{.Redirect}}</code>
      </p>
      <p style="margin-top:1rem; color:#666">
        Na login worden tokens opgeslagen in Postgres en kan je chatten via <code>/v1/chat/completions</code> met model prefix <code>gemini-</code>.
      </p>
    </div>
  </body>
</html>
`))

func GeminiLoginPage(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = geminiTpl.Execute(w, map[string]any{"Redirect": cfg.GoogleRedirectURL})
	}
}
