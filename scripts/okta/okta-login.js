/* eslint-disable */
// Do not edit this file directly. See okta-login.ts on how to edit.
!function(){"use strict";var t=function(t,n,l,e){var o,i,a,r,c,u=new URLSearchParams,d=new URLSearchParams(t),v=d.get("force_fallback");if(e&&!v){var s,g;o=null==(c=null==e||null===(s=e.getSignInWidgetConfig)||void 0===s?void 0:s.call(e))?void 0:c.relayState;var f=null==e||null===(g=e.getRequestContext)||void 0===g?void 0:g.call(e);i=function(t){var n;return null==t||null===(n=t.target)||void 0===n?void 0:n.clientId}(f),a=function(t){var n,l;if(null!=t&&null!==(n=t.target)&&void 0!==n&&n.label&&"jobs_site"===(null==t||null===(l=t.target)||void 0===l?void 0:l.label))return"jobs"}(f),r=function(t,n){var l,e;if(null!=n&&null!==(l=n.target)&&void 0!==l&&l.label&&"jobs_site"===(null==n||null===(e=n.target)||void 0===e?void 0:e.label))return encodeURIComponent(t.replace("profile","jobs"))}(n,f)}i&&!v||(i=d.get("client_id")||void 0),!o&&l.startsWith("/oauth2/")&&(d.delete("prompt"),u.set("fromURI",l+"?"+d.toString())),o&&u.set("fromURI",o),i&&u.set("appClientId",i),a&&u.set("clientId",a),r&&u.set("returnUrl",r);var w=d.get("activation_token");return w?"/welcome/".concat(w,"?").concat(u.toString()):"/signin?".concat(u.toString())}(window.location.search,window.location.origin,window.location.pathname,window.OktaUtil);window.location.replace(t)}();