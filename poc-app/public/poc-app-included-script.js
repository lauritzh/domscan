const queryStringExt = window.location.search
const urlParamsExt = new URLSearchParams(queryStringExt)

if (urlParamsExt.has('redirect_external')) {
  window.location = urlParamsExt.get('redirect_external')
}
