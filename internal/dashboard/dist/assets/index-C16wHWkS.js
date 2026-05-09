(function(){const e=document.createElement("link").relList;if(e&&e.supports&&e.supports("modulepreload"))return;for(const a of document.querySelectorAll('link[rel="modulepreload"]'))s(a);new MutationObserver(a=>{for(const i of a)if(i.type==="childList")for(const o of i.addedNodes)o.tagName==="LINK"&&o.rel==="modulepreload"&&s(o)}).observe(document,{childList:!0,subtree:!0});function r(a){const i={};return a.integrity&&(i.integrity=a.integrity),a.referrerPolicy&&(i.referrerPolicy=a.referrerPolicy),a.crossOrigin==="use-credentials"?i.credentials="include":a.crossOrigin==="anonymous"?i.credentials="omit":i.credentials="same-origin",i}function s(a){if(a.ep)return;a.ep=!0;const i=r(a);fetch(a.href,i)}})();/**
 * @license
 * Copyright 2019 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */const at=globalThis,$t=at.ShadowRoot&&(at.ShadyCSS===void 0||at.ShadyCSS.nativeShadow)&&"adoptedStyleSheets"in Document.prototype&&"replace"in CSSStyleSheet.prototype,yt=Symbol(),St=new WeakMap;let Kt=class{constructor(e,r,s){if(this._$cssResult$=!0,s!==yt)throw Error("CSSResult is not constructable. Use `unsafeCSS` or `css` instead.");this.cssText=e,this.t=r}get styleSheet(){let e=this.o;const r=this.t;if($t&&e===void 0){const s=r!==void 0&&r.length===1;s&&(e=St.get(r)),e===void 0&&((this.o=e=new CSSStyleSheet).replaceSync(this.cssText),s&&St.set(r,e))}return e}toString(){return this.cssText}};const ee=t=>new Kt(typeof t=="string"?t:t+"",void 0,yt),g=(t,...e)=>{const r=t.length===1?t[0]:e.reduce((s,a,i)=>s+(o=>{if(o._$cssResult$===!0)return o.cssText;if(typeof o=="number")return o;throw Error("Value passed to 'css' function must be a 'css' function result: "+o+". Use 'unsafeCSS' to pass non-literal values, but take care to ensure page security.")})(a)+t[i+1],t[0]);return new Kt(r,t,yt)},re=(t,e)=>{if($t)t.adoptedStyleSheets=e.map(r=>r instanceof CSSStyleSheet?r:r.styleSheet);else for(const r of e){const s=document.createElement("style"),a=at.litNonce;a!==void 0&&s.setAttribute("nonce",a),s.textContent=r.cssText,t.appendChild(s)}},Tt=$t?t=>t:t=>t instanceof CSSStyleSheet?(e=>{let r="";for(const s of e.cssRules)r+=s.cssText;return ee(r)})(t):t;/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */const{is:se,defineProperty:ae,getOwnPropertyDescriptor:ie,getOwnPropertyNames:oe,getOwnPropertySymbols:ne,getPrototypeOf:de}=Object,dt=globalThis,Ct=dt.trustedTypes,ce=Ct?Ct.emptyScript:"",le=dt.reactiveElementPolyfillSupport,K=(t,e)=>t,it={toAttribute(t,e){switch(e){case Boolean:t=t?ce:null;break;case Object:case Array:t=t==null?t:JSON.stringify(t)}return t},fromAttribute(t,e){let r=t;switch(e){case Boolean:r=t!==null;break;case Number:r=t===null?null:Number(t);break;case Object:case Array:try{r=JSON.parse(t)}catch{r=null}}return r}},xt=(t,e)=>!se(t,e),Ot={attribute:!0,type:String,converter:it,reflect:!1,useDefault:!1,hasChanged:xt};Symbol.metadata??=Symbol("metadata"),dt.litPropertyMetadata??=new WeakMap;let R=class extends HTMLElement{static addInitializer(e){this._$Ei(),(this.l??=[]).push(e)}static get observedAttributes(){return this.finalize(),this._$Eh&&[...this._$Eh.keys()]}static createProperty(e,r=Ot){if(r.state&&(r.attribute=!1),this._$Ei(),this.prototype.hasOwnProperty(e)&&((r=Object.create(r)).wrapped=!0),this.elementProperties.set(e,r),!r.noAccessor){const s=Symbol(),a=this.getPropertyDescriptor(e,s,r);a!==void 0&&ae(this.prototype,e,a)}}static getPropertyDescriptor(e,r,s){const{get:a,set:i}=ie(this.prototype,e)??{get(){return this[r]},set(o){this[r]=o}};return{get:a,set(o){const p=a?.call(this);i?.call(this,o),this.requestUpdate(e,p,s)},configurable:!0,enumerable:!0}}static getPropertyOptions(e){return this.elementProperties.get(e)??Ot}static _$Ei(){if(this.hasOwnProperty(K("elementProperties")))return;const e=de(this);e.finalize(),e.l!==void 0&&(this.l=[...e.l]),this.elementProperties=new Map(e.elementProperties)}static finalize(){if(this.hasOwnProperty(K("finalized")))return;if(this.finalized=!0,this._$Ei(),this.hasOwnProperty(K("properties"))){const r=this.properties,s=[...oe(r),...ne(r)];for(const a of s)this.createProperty(a,r[a])}const e=this[Symbol.metadata];if(e!==null){const r=litPropertyMetadata.get(e);if(r!==void 0)for(const[s,a]of r)this.elementProperties.set(s,a)}this._$Eh=new Map;for(const[r,s]of this.elementProperties){const a=this._$Eu(r,s);a!==void 0&&this._$Eh.set(a,r)}this.elementStyles=this.finalizeStyles(this.styles)}static finalizeStyles(e){const r=[];if(Array.isArray(e)){const s=new Set(e.flat(1/0).reverse());for(const a of s)r.unshift(Tt(a))}else e!==void 0&&r.push(Tt(e));return r}static _$Eu(e,r){const s=r.attribute;return s===!1?void 0:typeof s=="string"?s:typeof e=="string"?e.toLowerCase():void 0}constructor(){super(),this._$Ep=void 0,this.isUpdatePending=!1,this.hasUpdated=!1,this._$Em=null,this._$Ev()}_$Ev(){this._$ES=new Promise(e=>this.enableUpdating=e),this._$AL=new Map,this._$E_(),this.requestUpdate(),this.constructor.l?.forEach(e=>e(this))}addController(e){(this._$EO??=new Set).add(e),this.renderRoot!==void 0&&this.isConnected&&e.hostConnected?.()}removeController(e){this._$EO?.delete(e)}_$E_(){const e=new Map,r=this.constructor.elementProperties;for(const s of r.keys())this.hasOwnProperty(s)&&(e.set(s,this[s]),delete this[s]);e.size>0&&(this._$Ep=e)}createRenderRoot(){const e=this.shadowRoot??this.attachShadow(this.constructor.shadowRootOptions);return re(e,this.constructor.elementStyles),e}connectedCallback(){this.renderRoot??=this.createRenderRoot(),this.enableUpdating(!0),this._$EO?.forEach(e=>e.hostConnected?.())}enableUpdating(e){}disconnectedCallback(){this._$EO?.forEach(e=>e.hostDisconnected?.())}attributeChangedCallback(e,r,s){this._$AK(e,s)}_$ET(e,r){const s=this.constructor.elementProperties.get(e),a=this.constructor._$Eu(e,s);if(a!==void 0&&s.reflect===!0){const i=(s.converter?.toAttribute!==void 0?s.converter:it).toAttribute(r,s.type);this._$Em=e,i==null?this.removeAttribute(a):this.setAttribute(a,i),this._$Em=null}}_$AK(e,r){const s=this.constructor,a=s._$Eh.get(e);if(a!==void 0&&this._$Em!==a){const i=s.getPropertyOptions(a),o=typeof i.converter=="function"?{fromAttribute:i.converter}:i.converter?.fromAttribute!==void 0?i.converter:it;this._$Em=a;const p=o.fromAttribute(r,i.type);this[a]=p??this._$Ej?.get(a)??p,this._$Em=null}}requestUpdate(e,r,s,a=!1,i){if(e!==void 0){const o=this.constructor;if(a===!1&&(i=this[e]),s??=o.getPropertyOptions(e),!((s.hasChanged??xt)(i,r)||s.useDefault&&s.reflect&&i===this._$Ej?.get(e)&&!this.hasAttribute(o._$Eu(e,s))))return;this.C(e,r,s)}this.isUpdatePending===!1&&(this._$ES=this._$EP())}C(e,r,{useDefault:s,reflect:a,wrapped:i},o){s&&!(this._$Ej??=new Map).has(e)&&(this._$Ej.set(e,o??r??this[e]),i!==!0||o!==void 0)||(this._$AL.has(e)||(this.hasUpdated||s||(r=void 0),this._$AL.set(e,r)),a===!0&&this._$Em!==e&&(this._$Eq??=new Set).add(e))}async _$EP(){this.isUpdatePending=!0;try{await this._$ES}catch(r){Promise.reject(r)}const e=this.scheduleUpdate();return e!=null&&await e,!this.isUpdatePending}scheduleUpdate(){return this.performUpdate()}performUpdate(){if(!this.isUpdatePending)return;if(!this.hasUpdated){if(this.renderRoot??=this.createRenderRoot(),this._$Ep){for(const[a,i]of this._$Ep)this[a]=i;this._$Ep=void 0}const s=this.constructor.elementProperties;if(s.size>0)for(const[a,i]of s){const{wrapped:o}=i,p=this[a];o!==!0||this._$AL.has(a)||p===void 0||this.C(a,void 0,i,p)}}let e=!1;const r=this._$AL;try{e=this.shouldUpdate(r),e?(this.willUpdate(r),this._$EO?.forEach(s=>s.hostUpdate?.()),this.update(r)):this._$EM()}catch(s){throw e=!1,this._$EM(),s}e&&this._$AE(r)}willUpdate(e){}_$AE(e){this._$EO?.forEach(r=>r.hostUpdated?.()),this.hasUpdated||(this.hasUpdated=!0,this.firstUpdated(e)),this.updated(e)}_$EM(){this._$AL=new Map,this.isUpdatePending=!1}get updateComplete(){return this.getUpdateComplete()}getUpdateComplete(){return this._$ES}shouldUpdate(e){return!0}update(e){this._$Eq&&=this._$Eq.forEach(r=>this._$ET(r,this[r])),this._$EM()}updated(e){}firstUpdated(e){}};R.elementStyles=[],R.shadowRootOptions={mode:"open"},R[K("elementProperties")]=new Map,R[K("finalized")]=new Map,le?.({ReactiveElement:R}),(dt.reactiveElementVersions??=[]).push("2.1.2");/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */const wt=globalThis,zt=t=>t,ot=wt.trustedTypes,Pt=ot?ot.createPolicy("lit-html",{createHTML:t=>t}):void 0,Wt="$lit$",_=`lit$${Math.random().toFixed(9).slice(2)}$`,Vt="?"+_,pe=`<${Vt}>`,T=document,W=()=>T.createComment(""),V=t=>t===null||typeof t!="object"&&typeof t!="function",_t=Array.isArray,he=t=>_t(t)||typeof t?.[Symbol.iterator]=="function",vt=`[ 	
\f\r]`,B=/<(?:(!--|\/[^a-zA-Z])|(\/?[a-zA-Z][^>\s]*)|(\/?$))/g,Dt=/-->/g,Rt=/>/g,A=RegExp(`>|${vt}(?:([^\\s"'>=/]+)(${vt}*=${vt}*(?:[^ 	
\f\r"'\`<>=]|("|')|))|$)`,"g"),It=/'/g,Lt=/"/g,Gt=/^(?:script|style|textarea|title)$/i,ue=t=>(e,...r)=>({_$litType$:t,strings:e,values:r}),n=ue(1),I=Symbol.for("lit-noChange"),d=Symbol.for("lit-nothing"),Nt=new WeakMap,S=T.createTreeWalker(T,129);function Yt(t,e){if(!_t(t)||!t.hasOwnProperty("raw"))throw Error("invalid template strings array");return Pt!==void 0?Pt.createHTML(e):e}const ve=(t,e)=>{const r=t.length-1,s=[];let a,i=e===2?"<svg>":e===3?"<math>":"",o=B;for(let p=0;p<r;p++){const c=t[p];let h,f,u=-1,$=0;for(;$<c.length&&(o.lastIndex=$,f=o.exec(c),f!==null);)$=o.lastIndex,o===B?f[1]==="!--"?o=Dt:f[1]!==void 0?o=Rt:f[2]!==void 0?(Gt.test(f[2])&&(a=RegExp("</"+f[2],"g")),o=A):f[3]!==void 0&&(o=A):o===A?f[0]===">"?(o=a??B,u=-1):f[1]===void 0?u=-2:(u=o.lastIndex-f[2].length,h=f[1],o=f[3]===void 0?A:f[3]==='"'?Lt:It):o===Lt||o===It?o=A:o===Dt||o===Rt?o=B:(o=A,a=void 0);const y=o===A&&t[p+1].startsWith("/>")?" ":"";i+=o===B?c+pe:u>=0?(s.push(h),c.slice(0,u)+Wt+c.slice(u)+_+y):c+_+(u===-2?p:y)}return[Yt(t,i+(t[r]||"<?>")+(e===2?"</svg>":e===3?"</math>":"")),s]};class G{constructor({strings:e,_$litType$:r},s){let a;this.parts=[];let i=0,o=0;const p=e.length-1,c=this.parts,[h,f]=ve(e,r);if(this.el=G.createElement(h,s),S.currentNode=this.el.content,r===2||r===3){const u=this.el.content.firstChild;u.replaceWith(...u.childNodes)}for(;(a=S.nextNode())!==null&&c.length<p;){if(a.nodeType===1){if(a.hasAttributes())for(const u of a.getAttributeNames())if(u.endsWith(Wt)){const $=f[o++],y=a.getAttribute(u).split(_),st=/([.?@])?(.*)/.exec($);c.push({type:1,index:i,name:st[2],strings:y,ctor:st[1]==="."?me:st[1]==="?"?ge:st[1]==="@"?be:ct}),a.removeAttribute(u)}else u.startsWith(_)&&(c.push({type:6,index:i}),a.removeAttribute(u));if(Gt.test(a.tagName)){const u=a.textContent.split(_),$=u.length-1;if($>0){a.textContent=ot?ot.emptyScript:"";for(let y=0;y<$;y++)a.append(u[y],W()),S.nextNode(),c.push({type:2,index:++i});a.append(u[$],W())}}}else if(a.nodeType===8)if(a.data===Vt)c.push({type:2,index:i});else{let u=-1;for(;(u=a.data.indexOf(_,u+1))!==-1;)c.push({type:7,index:i}),u+=_.length-1}i++}}static createElement(e,r){const s=T.createElement("template");return s.innerHTML=e,s}}function L(t,e,r=t,s){if(e===I)return e;let a=s!==void 0?r._$Co?.[s]:r._$Cl;const i=V(e)?void 0:e._$litDirective$;return a?.constructor!==i&&(a?._$AO?.(!1),i===void 0?a=void 0:(a=new i(t),a._$AT(t,r,s)),s!==void 0?(r._$Co??=[])[s]=a:r._$Cl=a),a!==void 0&&(e=L(t,a._$AS(t,e.values),a,s)),e}class fe{constructor(e,r){this._$AV=[],this._$AN=void 0,this._$AD=e,this._$AM=r}get parentNode(){return this._$AM.parentNode}get _$AU(){return this._$AM._$AU}u(e){const{el:{content:r},parts:s}=this._$AD,a=(e?.creationScope??T).importNode(r,!0);S.currentNode=a;let i=S.nextNode(),o=0,p=0,c=s[0];for(;c!==void 0;){if(o===c.index){let h;c.type===2?h=new Z(i,i.nextSibling,this,e):c.type===1?h=new c.ctor(i,c.name,c.strings,this,e):c.type===6&&(h=new $e(i,this,e)),this._$AV.push(h),c=s[++p]}o!==c?.index&&(i=S.nextNode(),o++)}return S.currentNode=T,a}p(e){let r=0;for(const s of this._$AV)s!==void 0&&(s.strings!==void 0?(s._$AI(e,s,r),r+=s.strings.length-2):s._$AI(e[r])),r++}}class Z{get _$AU(){return this._$AM?._$AU??this._$Cv}constructor(e,r,s,a){this.type=2,this._$AH=d,this._$AN=void 0,this._$AA=e,this._$AB=r,this._$AM=s,this.options=a,this._$Cv=a?.isConnected??!0}get parentNode(){let e=this._$AA.parentNode;const r=this._$AM;return r!==void 0&&e?.nodeType===11&&(e=r.parentNode),e}get startNode(){return this._$AA}get endNode(){return this._$AB}_$AI(e,r=this){e=L(this,e,r),V(e)?e===d||e==null||e===""?(this._$AH!==d&&this._$AR(),this._$AH=d):e!==this._$AH&&e!==I&&this._(e):e._$litType$!==void 0?this.$(e):e.nodeType!==void 0?this.T(e):he(e)?this.k(e):this._(e)}O(e){return this._$AA.parentNode.insertBefore(e,this._$AB)}T(e){this._$AH!==e&&(this._$AR(),this._$AH=this.O(e))}_(e){this._$AH!==d&&V(this._$AH)?this._$AA.nextSibling.data=e:this.T(T.createTextNode(e)),this._$AH=e}$(e){const{values:r,_$litType$:s}=e,a=typeof s=="number"?this._$AC(e):(s.el===void 0&&(s.el=G.createElement(Yt(s.h,s.h[0]),this.options)),s);if(this._$AH?._$AD===a)this._$AH.p(r);else{const i=new fe(a,this),o=i.u(this.options);i.p(r),this.T(o),this._$AH=i}}_$AC(e){let r=Nt.get(e.strings);return r===void 0&&Nt.set(e.strings,r=new G(e)),r}k(e){_t(this._$AH)||(this._$AH=[],this._$AR());const r=this._$AH;let s,a=0;for(const i of e)a===r.length?r.push(s=new Z(this.O(W()),this.O(W()),this,this.options)):s=r[a],s._$AI(i),a++;a<r.length&&(this._$AR(s&&s._$AB.nextSibling,a),r.length=a)}_$AR(e=this._$AA.nextSibling,r){for(this._$AP?.(!1,!0,r);e!==this._$AB;){const s=zt(e).nextSibling;zt(e).remove(),e=s}}setConnected(e){this._$AM===void 0&&(this._$Cv=e,this._$AP?.(e))}}class ct{get tagName(){return this.element.tagName}get _$AU(){return this._$AM._$AU}constructor(e,r,s,a,i){this.type=1,this._$AH=d,this._$AN=void 0,this.element=e,this.name=r,this._$AM=a,this.options=i,s.length>2||s[0]!==""||s[1]!==""?(this._$AH=Array(s.length-1).fill(new String),this.strings=s):this._$AH=d}_$AI(e,r=this,s,a){const i=this.strings;let o=!1;if(i===void 0)e=L(this,e,r,0),o=!V(e)||e!==this._$AH&&e!==I,o&&(this._$AH=e);else{const p=e;let c,h;for(e=i[0],c=0;c<i.length-1;c++)h=L(this,p[s+c],r,c),h===I&&(h=this._$AH[c]),o||=!V(h)||h!==this._$AH[c],h===d?e=d:e!==d&&(e+=(h??"")+i[c+1]),this._$AH[c]=h}o&&!a&&this.j(e)}j(e){e===d?this.element.removeAttribute(this.name):this.element.setAttribute(this.name,e??"")}}class me extends ct{constructor(){super(...arguments),this.type=3}j(e){this.element[this.name]=e===d?void 0:e}}class ge extends ct{constructor(){super(...arguments),this.type=4}j(e){this.element.toggleAttribute(this.name,!!e&&e!==d)}}class be extends ct{constructor(e,r,s,a,i){super(e,r,s,a,i),this.type=5}_$AI(e,r=this){if((e=L(this,e,r,0)??d)===I)return;const s=this._$AH,a=e===d&&s!==d||e.capture!==s.capture||e.once!==s.once||e.passive!==s.passive,i=e!==d&&(s===d||a);a&&this.element.removeEventListener(this.name,this,s),i&&this.element.addEventListener(this.name,this,e),this._$AH=e}handleEvent(e){typeof this._$AH=="function"?this._$AH.call(this.options?.host??this.element,e):this._$AH.handleEvent(e)}}class $e{constructor(e,r,s){this.element=e,this.type=6,this._$AN=void 0,this._$AM=r,this.options=s}get _$AU(){return this._$AM._$AU}_$AI(e){L(this,e)}}const ye=wt.litHtmlPolyfillSupport;ye?.(G,Z),(wt.litHtmlVersions??=[]).push("3.3.2");const xe=(t,e,r)=>{const s=r?.renderBefore??e;let a=s._$litPart$;if(a===void 0){const i=r?.renderBefore??null;s._$litPart$=a=new Z(e.insertBefore(W(),i),i,void 0,r??{})}return a._$AI(t),a};/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */const kt=globalThis;class m extends R{constructor(){super(...arguments),this.renderOptions={host:this},this._$Do=void 0}createRenderRoot(){const e=super.createRenderRoot();return this.renderOptions.renderBefore??=e.firstChild,e}update(e){const r=this.render();this.hasUpdated||(this.renderOptions.isConnected=this.isConnected),super.update(e),this._$Do=xe(r,this.renderRoot,this.renderOptions)}connectedCallback(){super.connectedCallback(),this._$Do?.setConnected(!0)}disconnectedCallback(){super.disconnectedCallback(),this._$Do?.setConnected(!1)}render(){return I}}m._$litElement$=!0,m.finalized=!0,kt.litElementHydrateSupport?.({LitElement:m});const we=kt.litElementPolyfillSupport;we?.({LitElement:m});(kt.litElementVersions??=[]).push("4.2.2");/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */const b=t=>(e,r)=>{r!==void 0?r.addInitializer(()=>{customElements.define(t,e)}):customElements.define(t,e)};/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */const _e={attribute:!0,type:String,converter:it,reflect:!1,hasChanged:xt},ke=(t=_e,e,r)=>{const{kind:s,metadata:a}=r;let i=globalThis.litPropertyMetadata.get(a);if(i===void 0&&globalThis.litPropertyMetadata.set(a,i=new Map),s==="setter"&&((t=Object.create(t)).wrapped=!0),i.set(r.name,t),s==="accessor"){const{name:o}=r;return{set(p){const c=e.get.call(this);e.set.call(this,p),this.requestUpdate(o,c,t,!0,p)},init(p){return p!==void 0&&this.C(o,void 0,t,p),p}}}if(s==="setter"){const{name:o}=r;return function(p){const c=this[o];e.call(this,p),this.requestUpdate(o,c,t,!0,p)}}throw Error("Unsupported decorator location: "+s)};function H(t){return(e,r)=>typeof r=="object"?ke(t,e,r):((s,a,i)=>{const o=a.hasOwnProperty(i);return a.constructor.createProperty(i,s),o?Object.getOwnPropertyDescriptor(a,i):void 0})(t,e,r)}/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */function l(t){return H({...t,state:!0,attribute:!1})}var Ee=Object.defineProperty,Ae=Object.getOwnPropertyDescriptor,Et=(t,e,r,s)=>{for(var a=s>1?void 0:s?Ae(e,r):e,i=t.length-1,o;i>=0;i--)(o=t[i])&&(a=(s?o(e,r,a):o(a))||a);return s&&a&&Ee(e,r,a),a};let Y=class extends m{constructor(){super(...arguments),this.view="overview",this.paletteOpen=!1,this.onGlobalKey=t=>{if((t.ctrlKey||t.metaKey)&&t.key.toLowerCase()==="k"){t.preventDefault(),this.paletteOpen=!this.paletteOpen;return}if(t.key===":"&&!this.paletteOpen){const r=t.target;if(r instanceof HTMLInputElement||r instanceof HTMLTextAreaElement||r instanceof HTMLSelectElement||(r?.isContentEditable??!1))return;t.preventDefault(),this.paletteOpen=!0}},this.closePalette=()=>{this.paletteOpen=!1},this.syncFromHash=()=>{const t=window.location.hash.replace(/^#\/?/,"");["overview","alerts","inventory","policy","audit","logs","setup"].includes(t)&&(this.view=t)}}connectedCallback(){super.connectedCallback(),this.syncFromHash(),window.addEventListener("hashchange",this.syncFromHash),window.addEventListener("keydown",this.onGlobalKey),this.addEventListener("dc:palette-close",this.closePalette)}disconnectedCallback(){super.disconnectedCallback(),window.removeEventListener("hashchange",this.syncFromHash),window.removeEventListener("keydown",this.onGlobalKey),this.removeEventListener("dc:palette-close",this.closePalette)}render(){return n`
      <dc-sidebar .active=${this.view}></dc-sidebar>
      <main>
        <dc-token-banner></dc-token-banner>
        <dc-statusbar></dc-statusbar>
        <section class="view">${this.renderView()}</section>
      </main>
      <dc-command-palette .open=${this.paletteOpen}></dc-command-palette>
    `}renderView(){switch(this.view){case"overview":return n`<dc-overview></dc-overview>`;case"alerts":return n`<dc-alerts></dc-alerts>`;case"inventory":return n`<dc-inventory></dc-inventory>`;case"policy":return n`<dc-policy></dc-policy>`;case"audit":return n`<dc-audit></dc-audit>`;case"logs":return n`<dc-logs></dc-logs>`;case"setup":return n`<dc-setup></dc-setup>`}}};Y.styles=g`
    :host {
      display: grid;
      grid-template-columns: var(--dc-sidebar-w) minmax(0, 1fr);
      grid-template-rows: 100vh;
      height: 100vh;
      width: 100vw;
    }

    main {
      display: grid;
      grid-template-rows: auto var(--dc-statusbar-h) minmax(0, 1fr);
      min-width: 0;
      min-height: 0;
    }

    .view {
      overflow: auto;
      padding: var(--dc-space-4);
    }

    .placeholder {
      color: var(--dc-text-muted);
      font-style: italic;
      padding: var(--dc-space-5);
      border: 1px dashed var(--dc-border);
      border-radius: var(--dc-radius-md);
    }
  `;Et([l()],Y.prototype,"view",2);Et([l()],Y.prototype,"paletteOpen",2);Y=Et([b("dc-app")],Y);var Se=Object.defineProperty,Te=Object.getOwnPropertyDescriptor,Jt=(t,e,r,s)=>{for(var a=s>1?void 0:s?Te(e,r):e,i=t.length-1,o;i>=0;i--)(o=t[i])&&(a=(s?o(e,r,a):o(a))||a);return s&&a&&Se(e,r,a),a};const Ce=[{title:"OPERATE",items:[{id:"overview",label:"OVERVIEW",key:"1"},{id:"alerts",label:"ALERTS",key:"2"},{id:"inventory",label:"INVENTORY",key:"3"},{id:"policy",label:"POLICY",key:"4"}]},{title:"EVIDENCE",items:[{id:"audit",label:"AUDIT",key:"5"},{id:"logs",label:"LOGS",key:"6"},{id:"setup",label:"SETUP",key:"7"}]}];let nt=class extends m{constructor(){super(...arguments),this.active="overview"}render(){return n`
      <div class="brand">
        <span class="brand-mark">DEFENSECLAW</span>
        <span class="brand-sub">v0.1</span>
      </div>
      ${Ce.map(t=>n`
        <div class="group">
          <div class="group-title">${t.title}</div>
          ${t.items.map(e=>n`
            <a class="nav-item ${this.active===e.id?"active":""}"
               href="#/${e.id}">
              <span class="key">${e.key}</span>
              <span>${e.label}</span>
            </a>
          `)}
        </div>
      `)}
      <div class="footer">
        <div class="dc-hint">: or ctrl+k for palette</div>
        <div>? for help</div>
      </div>
    `}};nt.styles=g`
    :host {
      display: flex;
      flex-direction: column;
      gap: var(--dc-space-4);
      padding: var(--dc-space-3);
      background: var(--dc-surface-1);
      border-right: 1px solid var(--dc-border);
      overflow-y: auto;
    }

    .brand {
      display: flex;
      align-items: baseline;
      gap: var(--dc-space-2);
      padding: var(--dc-space-2) 0;
      border-bottom: 1px solid var(--dc-border);
    }
    .brand-mark {
      font-weight: 700;
      color: var(--dc-accent);
      letter-spacing: 0.18em;
    }
    .brand-sub {
      font-size: var(--dc-fs-xs);
      color: var(--dc-text-faint);
      letter-spacing: 0.10em;
      text-transform: uppercase;
    }

    .group { display: flex; flex-direction: column; gap: var(--dc-space-1); }
    .group-title {
      font-size: var(--dc-fs-xs);
      color: var(--dc-text-faint);
      letter-spacing: 0.18em;
      padding: 0 var(--dc-space-2) var(--dc-space-1);
    }

    .nav-item {
      display: grid;
      grid-template-columns: 18px 1fr;
      align-items: center;
      gap: var(--dc-space-2);
      padding: 6px var(--dc-space-2);
      border: 1px solid transparent;
      border-radius: var(--dc-radius-sm);
      color: var(--dc-text-muted);
      letter-spacing: 0.10em;
      cursor: pointer;
    }
    .nav-item:hover { background: var(--dc-row-hover); color: var(--dc-text); }
    .nav-item.active {
      color: var(--dc-text-bright);
      background: var(--dc-surface-2);
      border-color: var(--dc-primary);
    }
    .key {
      color: var(--dc-text-faint);
      font-size: var(--dc-fs-xs);
    }
    .nav-item.active .key { color: var(--dc-accent); }

    .footer {
      margin-top: auto;
      padding-top: var(--dc-space-2);
      border-top: 1px solid var(--dc-border);
      font-size: var(--dc-fs-xs);
      color: var(--dc-text-faint);
      line-height: 1.5;
    }
  `;Jt([H({type:String})],nt.prototype,"active",2);nt=Jt([b("dc-sidebar")],nt);const mt="dc.token",Oe="dc-web/0.1";function ze(){return localStorage.getItem(mt)}function Zt(t){t?localStorage.setItem(mt,t):localStorage.removeItem(mt)}function Pe(t,e){const r=new Error(`HTTP ${t}`);return r.status=t,r.body=e,r}async function q(t,e,r){const s={Accept:"application/json"},a=ze();a&&(s.Authorization=`Bearer ${a}`);const i={method:t,headers:s};r!==void 0&&(s["Content-Type"]="application/json",s["X-DefenseClaw-Client"]=Oe,i.body=JSON.stringify(r));const o=await fetch(e,i),p=await o.text();let c=null;if(p)try{c=JSON.parse(p)}catch{c=p}if(!o.ok)throw o.status===401&&window.dispatchEvent(new CustomEvent("dc:auth-failure",{detail:{path:e,method:t,body:c}})),Pe(o.status,c);return c}const v={get:t=>q("GET",t),post:(t,e)=>q("POST",t,e??{}),put:(t,e)=>q("PUT",t,e??{}),patch:(t,e)=>q("PATCH",t,e??{}),delete:t=>q("DELETE",t)};class x{constructor(e,r,s=5e3){this.state={value:null,error:null,freshness:"loading",lastFetched:null},this.timer=null,this.inflight=!1,this.onVisibility=()=>{document.hidden||this.tick()},this.host=e,this.fetcher=r,this.intervalMs=s,e.addController(this)}hostConnected(){this.tick(),this.timer=window.setInterval(()=>void this.tick(),this.intervalMs),document.addEventListener("visibilitychange",this.onVisibility)}hostDisconnected(){this.timer!==null&&window.clearInterval(this.timer),this.timer=null,document.removeEventListener("visibilitychange",this.onVisibility)}refresh(){return this.tick()}async tick(){if(!(this.inflight||document.hidden)){this.inflight=!0;try{const e=await this.fetcher();this.state={value:e,error:null,freshness:"live",lastFetched:Date.now()}}catch(e){this.state={...this.state,error:e,freshness:this.state.value?"stale":"error"}}finally{this.inflight=!1,this.host.requestUpdate()}}}}var De=Object.getOwnPropertyDescriptor,Re=(t,e,r,s)=>{for(var a=s>1?void 0:s?De(e,r):e,i=t.length-1,o;i>=0;i--)(o=t[i])&&(a=o(a)||a);return a};const Ie="●",Qt="○";function Ut(t){switch(t){case"running":return"var(--dc-clean)";case"starting":case"reconnecting":case"degraded":return"var(--dc-medium)";case"error":case"stopped":return"var(--dc-critical)";default:return"var(--dc-text-faint)"}}function Le(t){return t==="running"||t==="degraded"||t==="starting"||t==="reconnecting"?Ie:Qt}function Ne(t){const e=Math.floor(t/1e3),r=Math.floor(e/3600),s=Math.floor(e%3600/60),a=e%60;return r>0?`${r}h ${s}m`:s>0?`${s}m ${a}s`:`${a}s`}let gt=class extends m{constructor(){super(...arguments),this.poll=new x(this,()=>v.get("/health"),5e3)}render(){const t=this.poll.state.value,e=this.poll.state.freshness;if(!t)return n`
        <span class="pill">
          <span style="color: ${Ut("stopped")};">${Qt}</span>
          <span class="label">SIDECAR</span>
          <span class="value">${e==="loading"?"loading…":"offline"}</span>
        </span>
      `;const r=[["GATEWAY",t.gateway?.state,""],["GUARDRAIL",t.guardrail?.state,String(t.guardrail?.details?.mode??"")],["WATCHER",t.watcher?.state,""],["SINKS",t.sinks?.state,""],["TELEMETRY",t.telemetry?.state,""]];return n`
      ${r.map(([s,a,i])=>n`
        <span class="pill">
          <span style="color: ${Ut(a)};">${Le(a)}</span>
          <span class="label">${s}</span>
          <span class="value">${a??"—"}${i?` / ${i}`:""}</span>
        </span>
      `)}
      <span class="pill freshness">
        <span class="label">UPTIME</span>
        <span class="value">${Ne(t.uptime_ms)}</span>
      </span>
      <span class="pill">
        <span class="label">v</span>
        <span class="value">${t.provenance?.binary_version??"?"}</span>
      </span>
    `}};gt.styles=g`
    :host {
      display: flex;
      align-items: center;
      gap: var(--dc-space-4);
      height: var(--dc-statusbar-h);
      padding: 0 var(--dc-space-4);
      background: var(--dc-surface-1);
      border-bottom: 1px solid var(--dc-border);
      font-size: var(--dc-fs-sm);
      letter-spacing: 0.06em;
      overflow-x: auto;
      white-space: nowrap;
    }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      color: var(--dc-text-muted);
    }
    .label { color: var(--dc-text-faint); }
    .value { color: var(--dc-text); }
    .freshness { margin-left: auto; }
  `;gt=Re([b("dc-statusbar")],gt);var Ue=Object.defineProperty,Me=Object.getOwnPropertyDescriptor,lt=(t,e,r,s)=>{for(var a=s>1?void 0:s?Me(e,r):e,i=t.length-1,o;i>=0;i--)(o=t[i])&&(a=(s?o(e,r,a):o(a))||a);return s&&a&&Ue(e,r,a),a};let N=class extends m{constructor(){super(...arguments),this.visible=!1,this.lastPath="",this.dismissed=!1,this.onAuthFailure=t=>{if(this.dismissed)return;const e=t;this.lastPath=e.detail?.path??"",this.visible=!0},this.onSubmit=t=>{t.preventDefault();const s=t.target.elements.namedItem("token")?.value.trim()??"";s&&(Zt(s),window.location.reload())},this.dismiss=()=>{this.dismissed=!0,this.visible=!1}}connectedCallback(){super.connectedCallback(),window.addEventListener("dc:auth-failure",this.onAuthFailure),localStorage.getItem("dc.token")||(this.visible=!0)}disconnectedCallback(){super.disconnectedCallback(),window.removeEventListener("dc:auth-failure",this.onAuthFailure)}render(){return this.visible?n`
      <div class="banner" role="alert">
        <span class="icon">// AUTH REQUIRED</span>
        <span class="msg">
          Gateway has token auth on. Paste <code>$DEFENSECLAW_GATEWAY_TOKEN</code> to unblock the dashboard.
          ${this.lastPath?n`<span class="hint">last failure: ${this.lastPath}</span>`:d}
        </span>
        <form @submit=${this.onSubmit}>
          <input
            type="password"
            name="token"
            placeholder="bearer token"
            autocomplete="off"
            spellcheck="false"
            autofocus
          />
          <button type="submit">SAVE &amp; RELOAD</button>
        </form>
        <button class="dismiss" @click=${this.dismiss} title="dismiss until next refresh">×</button>
      </div>
    `:d}};N.styles=g`
    :host { display: block; }

    .banner {
      display: grid;
      grid-template-columns: auto 1fr auto auto;
      gap: var(--dc-space-3);
      align-items: center;
      padding: 10px 16px;
      background: var(--dc-surface-2);
      border-bottom: 2px solid var(--dc-medium);
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-sm);
    }
    .icon {
      color: var(--dc-medium);
      font-weight: 700;
      letter-spacing: 0.10em;
    }
    .msg { color: var(--dc-text); }
    .msg .hint {
      display: block;
      color: var(--dc-text-faint);
      font-size: var(--dc-fs-xs);
      margin-top: 2px;
    }
    form {
      display: flex;
      gap: var(--dc-space-2);
      align-items: center;
    }
    input {
      background: var(--dc-bg);
      color: var(--dc-text);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      padding: 6px 10px;
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-md);
      min-width: 280px;
    }
    input:focus { outline: none; border-color: var(--dc-primary); }
    button.dismiss {
      padding: 4px 10px;
      color: var(--dc-text-muted);
    }
  `;lt([l()],N.prototype,"visible",2);lt([l()],N.prototype,"lastPath",2);lt([l()],N.prototype,"dismissed",2);N=lt([b("dc-token-banner")],N);var je=Object.defineProperty,He=Object.getOwnPropertyDescriptor,pt=(t,e,r,s)=>{for(var a=s>1?void 0:s?He(e,r):e,i=t.length-1,o;i>=0;i--)(o=t[i])&&(a=(s?o(e,r,a):o(a))||a);return s&&a&&je(e,r,a),a};let U=class extends m{constructor(){super(...arguments),this.heading="",this.qualifier="",this.hasFooter=!1}render(){return n`
      <header>
        <span>
          <span class="title">${this.heading}</span>
          ${this.qualifier?n`<span class="qualifier"> · ${this.qualifier}</span>`:""}
        </span>
        <slot name="actions"></slot>
      </header>
      <div class="body"><slot></slot></div>
      ${this.hasFooter?n`<footer><slot name="footer"></slot></footer>`:""}
    `}};U.styles=g`
    :host {
      display: block;
      background: var(--dc-surface-1);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-md);
      overflow: hidden;
    }
    :host([accent]) { border-color: var(--dc-primary); }
    :host([critical]) { border-left: 3px solid var(--dc-critical); }

    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: var(--dc-space-2) var(--dc-space-3);
      border-bottom: 1px solid var(--dc-border);
      background: var(--dc-surface-2);
      gap: var(--dc-space-3);
    }
    .title {
      font-size: var(--dc-fs-sm);
      font-weight: 700;
      letter-spacing: 0.14em;
      color: var(--dc-accent);
      text-transform: uppercase;
    }
    .qualifier {
      font-size: var(--dc-fs-xs);
      color: var(--dc-text-faint);
      letter-spacing: 0.08em;
    }
    .body { padding: var(--dc-space-3); }
    footer {
      padding: var(--dc-space-1) var(--dc-space-3);
      border-top: 1px solid var(--dc-border);
      font-size: var(--dc-fs-xs);
      color: var(--dc-text-faint);
    }
    ::slotted([slot="actions"]) {
      display: inline-flex;
      gap: var(--dc-space-2);
    }
  `;pt([H()],U.prototype,"heading",2);pt([H()],U.prototype,"qualifier",2);pt([H({type:Boolean})],U.prototype,"hasFooter",2);U=pt([b("dc-panel")],U);var Fe=Object.getOwnPropertyDescriptor,Be=(t,e,r,s)=>{for(var a=s>1?void 0:s?Fe(e,r):e,i=t.length-1,o;i>=0;i--)(o=t[i])&&(a=o(a)||a);return a};const qe=[["api","API"],["gateway","GATEWAY"],["guardrail","GUARDRAIL"],["watcher","WATCHER"],["sinks","SINKS"],["telemetry","TELEMETRY"]];function Mt(t){switch(t){case"running":return"var(--dc-clean)";case"starting":case"reconnecting":case"degraded":return"var(--dc-medium)";case"error":case"stopped":return"var(--dc-critical)";default:return"var(--dc-text-faint)"}}function jt(t){if(!t)return"—";const e=new Date(t).getTime();if(Number.isNaN(e))return"—";const r=Math.max(0,Date.now()-e),s=Math.floor(r/1e3);if(s<60)return`${s}s ago`;const a=Math.floor(s/60);return a<60?`${a}m ago`:`${Math.floor(a/60)}h ${a%60}m ago`}function Ke(t){if(!t?.details)return"";const e=[];for(const[r,s]of Object.entries(t.details))s==null||s===""||e.push(`${r}=${typeof s=="object"?JSON.stringify(s):String(s)}`);return e.join("  ")}let bt=class extends m{constructor(){super(...arguments),this.health=new x(this,()=>v.get("/health"),5e3),this.counts=new x(this,()=>v.get("/v1/audit/counts"),3e4),this.investigations=new x(this,()=>v.get("/v1/audit?limit=20"),1e4)}renderInvestigationRows(){const t=this.investigations.state.value?.events??[];return t.length===0?n`<tr><td colspan="4" class="detail dc-hint">no recent events</td></tr>`:t.slice(0,8).map(e=>{const r=(e.severity??"INFO").toUpperCase(),s=new Date(e.timestamp).toLocaleTimeString();let a="var(--dc-info)";return r==="CRITICAL"?a="var(--dc-critical)":r==="HIGH"?a="var(--dc-high)":r==="MEDIUM"?a="var(--dc-medium)":r==="LOW"&&(a="var(--dc-low)"),n`
        <tr>
          <td class="mono">${s}</td>
          <td class="mono" style="color: ${a};">${r}</td>
          <td class="mono">${e.action}</td>
          <td class="detail" title=${e.target}>${e.target||"—"}</td>
        </tr>
      `})}render(){const t=this.health.state.value,e=this.health.state.freshness,r=this.health.state.error,s=this.counts.state.value;return n`
      <div class="page-header">
        <div>
          <h1>// SECURITY OPERATIONS OVERVIEW</h1>
          <div class="subtitle dc-hint">
            Live governance state for OpenClaw runs, tool calls, policies, and audit evidence.
          </div>
        </div>
        <div>
          ${e==="stale"?n`<span class="stale">stale — last fetch failed</span>`:e==="error"?n`<span class="err">offline — ${r?.message??"unknown error"}</span>`:d}
        </div>
      </div>

      <div class="grid">
        <dc-panel class="span-3" heading="ACTIVE ALERTS" qualifier="audit store">
          <div class="stat">
            <div class="value" style="color: var(--dc-critical);">${s?.alerts??"—"}</div>
            <div class="note">
              ${s?`${s.blocked_skills+s.blocked_mcps} blocked components · ${s.blocked_egress_calls} blocked egress calls`:"loading…"}
            </div>
          </div>
        </dc-panel>

        <dc-panel class="span-3" heading="GUARDRAIL" qualifier="mode">
          <div class="stat">
            <div class="value" style="color: var(--dc-accent);">
              ${t?.guardrail?.details?.mode??"—"}
            </div>
            <div class="note">Listener ${t?.guardrail?.details?.addr??"—"}</div>
          </div>
        </dc-panel>

        <dc-panel class="span-3" heading="SINKS" qualifier="health">
          <div class="stat">
            <div class="value" style="color: ${Mt(t?.sinks?.state)};">
              ${t?.sinks?.state??"—"}
            </div>
            <div class="note">Forwarder pipeline state.</div>
          </div>
        </dc-panel>

        <dc-panel class="span-3" heading="UPTIME" qualifier="started">
          <div class="stat">
            <div class="value">${jt(t?.started_at)}</div>
            <div class="note">Binary v${t?.provenance?.binary_version??"?"} · schema v${t?.provenance?.schema_version??"?"}</div>
          </div>
        </dc-panel>

        <dc-panel class="span-6" heading="SUBSYSTEMS" qualifier="from /health">
          <table>
            <thead>
              <tr><th></th><th>Subsystem</th><th>State</th><th>Since</th><th>Detail</th></tr>
            </thead>
            <tbody>
              ${qe.map(([a,i])=>{const o=t?.[a];return n`
                  <tr>
                    <td><span class="dot" style="color: ${Mt(o?.state)};">●</span></td>
                    <td class="mono">${i}</td>
                    <td class="mono">${o?.state??"—"}</td>
                    <td class="mono">${jt(o?.since)}</td>
                    <td class="detail">${Ke(o)}</td>
                  </tr>
                `})}
            </tbody>
          </table>
        </dc-panel>

        <dc-panel class="span-6" heading="RECENT EVENTS" qualifier="last 20 from /v1/audit">
          <table>
            <thead>
              <tr><th>Time</th><th>Severity</th><th>Action</th><th>Target</th></tr>
            </thead>
            <tbody>
              ${this.renderInvestigationRows()}
            </tbody>
          </table>
        </dc-panel>

        <dc-panel class="span-12" heading="PROVENANCE" qualifier="binary identity">
          <table>
            <tbody>
              <tr>
                <td class="mono" style="color: var(--dc-text-faint); width: 200px;">binary_version</td>
                <td class="mono">${t?.provenance?.binary_version??"—"}</td>
              </tr>
              <tr>
                <td class="mono" style="color: var(--dc-text-faint);">schema_version</td>
                <td class="mono">${t?.provenance?.schema_version??"—"}</td>
              </tr>
              <tr>
                <td class="mono" style="color: var(--dc-text-faint);">content_hash</td>
                <td class="mono" style="font-size: var(--dc-fs-xs);">${t?.provenance?.content_hash??"—"}</td>
              </tr>
              <tr>
                <td class="mono" style="color: var(--dc-text-faint);">generation</td>
                <td class="mono">${t?.provenance?.generation??"—"}</td>
              </tr>
            </tbody>
          </table>
        </dc-panel>
      </div>
    `}};bt.styles=g`
    :host { display: grid; gap: var(--dc-space-4); }

    .page-header {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: var(--dc-space-3);
    }
    h1 {
      font-size: var(--dc-fs-lg);
      letter-spacing: 0.18em;
      color: var(--dc-text-bright);
      margin: 0;
      text-transform: uppercase;
    }
    .subtitle {
      color: var(--dc-text-faint);
      font-size: var(--dc-fs-sm);
      letter-spacing: 0.06em;
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(12, 1fr);
      gap: var(--dc-space-3);
    }
    .span-3 { grid-column: span 3; }
    .span-6 { grid-column: span 6; }
    .span-12 { grid-column: span 12; }
    @media (max-width: 1199px) {
      .span-3 { grid-column: span 6; }
      .span-6 { grid-column: span 12; }
    }
    @media (max-width: 599px) {
      .span-3 { grid-column: span 12; }
    }

    .stat .value {
      font-size: 28px;
      font-weight: 700;
      color: var(--dc-text-bright);
      letter-spacing: 0.04em;
    }
    .stat .note {
      font-size: var(--dc-fs-xs);
      color: var(--dc-text-faint);
      margin-top: var(--dc-space-1);
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: var(--dc-fs-sm);
    }
    th, td {
      text-align: left;
      padding: 6px 10px;
      border-bottom: 1px solid var(--dc-border);
    }
    th {
      color: var(--dc-text-faint);
      font-weight: 700;
      letter-spacing: 0.10em;
      text-transform: uppercase;
      font-size: var(--dc-fs-xs);
    }
    td.mono { color: var(--dc-text); }
    td.detail {
      color: var(--dc-text-muted);
      font-size: var(--dc-fs-xs);
    }
    .dot { display: inline-block; width: 10px; }

    .stale {
      color: var(--dc-medium);
      font-style: italic;
      font-size: var(--dc-fs-xs);
    }
    .err {
      color: var(--dc-critical);
      font-size: var(--dc-fs-sm);
    }
  `;bt=Be([b("dc-overview")],bt);var We=Object.defineProperty,Ve=Object.getOwnPropertyDescriptor,E=(t,e,r,s)=>{for(var a=s>1?void 0:s?Ve(e,r):e,i=t.length-1,o;i>=0;i--)(o=t[i])&&(a=(s?o(e,r,a):o(a))||a);return s&&a&&We(e,r,a),a};let w=class extends m{constructor(){super(...arguments),this.wizards=[],this.loadError="",this.selected=null,this.positional="",this.flags=[],this.status={kind:"idle"},this.events=[],this.abortController=null,this.cancel=()=>{this.abortController&&(this.abortController.abort(),this.abortController=null)}}disconnectedCallback(){super.disconnectedCallback(),this.cancel()}connectedCallback(){super.connectedCallback(),this.loadWizards()}async loadWizards(){try{const t=await v.get("/v1/setup/wizards");this.wizards=t.wizards}catch(t){const e=t;this.loadError=e.status?`GET /v1/setup/wizards → HTTP ${e.status}`:`failed: ${e.message}`}}select(t){this.selected=t,this.positional=t.allowed_positional?.[0]??"",this.flags=[{key:"",value:""}],this.events=[],this.status={kind:"idle"}}addFlag(){this.flags=[...this.flags,{key:"",value:""}]}removeFlag(t){this.flags=this.flags.filter((e,r)=>r!==t)}updateFlag(t,e,r){this.flags=this.flags.map((s,a)=>a===t?{...s,[e]:r}:s)}async run(){if(!this.selected)return;this.status={kind:"running"},this.events=[],this.abortController=new AbortController;const t={};for(const h of this.flags){const f=h.key.trim();f&&(t[f]=h.value)}const e={"Content-Type":"application/json","X-DefenseClaw-Client":"dc-web/0.1",Accept:"application/x-ndjson"},r=localStorage.getItem("dc.token");r&&(e.Authorization=`Bearer ${r}`);let s;try{s=await fetch("/v1/setup/run",{method:"POST",headers:e,signal:this.abortController.signal,body:JSON.stringify({wizard:this.selected.name,positional:this.positional||void 0,flags:t})})}catch(h){if(h.name==="AbortError"){this.appendEvent({event:"cancelled"}),this.status={kind:"cancelled"};return}this.appendEvent({event:"stderr",line:`network error: ${h.message}`}),this.status={kind:"done",code:-1};return}if(!s.ok||!s.body){const h=await s.text();this.appendEvent({event:"stderr",line:`HTTP ${s.status}: ${h}`}),this.status={kind:"done",code:s.status};return}const a=s.body.getReader(),i=new TextDecoder;let o="",p=0,c=!1;try{for(;;){const{value:h,done:f}=await a.read();if(f)break;o+=i.decode(h,{stream:!0});const u=o.split(`
`);o=u.pop()??"";for(const $ of u)if($.trim())try{const y=JSON.parse($);this.appendEvent(y),y.event==="exit"&&(p=y.code),y.event==="cancelled"&&(c=!0)}catch{this.appendEvent({event:"stderr",line:`parse error: ${$}`})}}}catch(h){if(h.name==="AbortError"){this.appendEvent({event:"cancelled"}),this.status={kind:"cancelled"},this.abortController=null;return}throw h}this.abortController=null,this.status=c?{kind:"cancelled"}:{kind:"done",code:p}}appendEvent(t){this.events=[...this.events,t]}render(){return this.loadError?n`<div class="empty">${this.loadError}</div>`:this.wizards.length===0?n`<div class="empty">loading wizards…</div>`:n`
      <div>
        <div class="dc-section" style="margin-bottom: var(--dc-space-2);">PICK A WIZARD</div>
        <div class="cards">
          ${this.wizards.map(t=>n`
            <button
              class="card ${this.selected?.name===t.name?"selected":""}"
              @click=${()=>this.select(t)}
            >
              <div class="card-name">${t.name.toUpperCase().replace(/-/g," ")}</div>
              <div class="card-sub">defenseclaw ${t.argv_prefix.join(" ")}</div>
            </button>
          `)}
        </div>
      </div>

      ${this.selected?this.renderForm(this.selected):d}
      ${this.events.length>0?this.renderOutput():d}
    `}renderForm(t){const e=this.status.kind==="running";return n`
      <form class="form" @submit=${r=>{r.preventDefault(),this.run()}}>
        <div class="form-row">
          <label>WIZARD</label>
          <code>${t.argv_prefix.join(" ")} ${t.require_positional?"&lt;positional&gt;":""} --non-interactive</code>
          <span></span>
        </div>

        ${t.require_positional?n`
          <div class="form-row">
            <label>POSITIONAL</label>
            ${t.allowed_positional&&t.allowed_positional.length>0?n`
              <select
                .value=${this.positional}
                @change=${r=>{this.positional=r.target.value}}
                ?disabled=${e}
              >
                ${t.allowed_positional.map(r=>n`<option value=${r} ?selected=${r===this.positional}>${r}</option>`)}
              </select>
            `:n`
              <input
                type="text"
                .value=${this.positional}
                @input=${r=>{this.positional=r.target.value}}
                ?disabled=${e}
                placeholder="required"
              />
            `}
            <span></span>
          </div>
        `:d}

        <div class="flags-header">
          <span class="dc-section">FLAGS</span>
          <button type="button" @click=${()=>this.addFlag()} ?disabled=${e}>+ ADD</button>
        </div>

        ${this.flags.map((r,s)=>n`
          <div class="form-row">
            <input
              type="text"
              placeholder="flag-name (e.g. realm)"
              .value=${r.key}
              @input=${a=>this.updateFlag(s,"key",a.target.value)}
              ?disabled=${e}
            />
            <input
              type="text"
              placeholder="value"
              .value=${r.value}
              @input=${a=>this.updateFlag(s,"value",a.target.value)}
              ?disabled=${e}
            />
            <button type="button" @click=${()=>this.removeFlag(s)} ?disabled=${e}>×</button>
          </div>
        `)}

        <div class="form-actions">
          ${e?n`
            <button type="button" class="action danger" @click=${this.cancel}>STOP</button>
          `:d}
          <button type="submit" ?disabled=${e}>
            ${e?"RUNNING…":"RUN"}
          </button>
        </div>
      </form>
    `}renderOutput(){return n`
      <div>
        <div class="dc-section" style="margin-bottom: var(--dc-space-2);">OUTPUT</div>
        <pre>${this.events.map(t=>this.renderEvent(t))}</pre>
      </div>
    `}renderEvent(t){if(t.event==="start")return n`<span class="stream-meta">$ ${t.argv.join(" ")}</span>\n`;if(t.event==="stdout")return n`<span class="stream-stdout">${t.line}</span>\n`;if(t.event==="stderr")return n`<span class="stream-stderr">${t.line}</span>\n`;if(t.event==="exit"){const e=t.code===0?"stream-exit-ok":"stream-exit-fail";return n`<span class=${e}>--- exit ${t.code} ---</span>\n`}return t.event==="cancelled"?n`<span class="stream-cancelled">--- cancelled by operator ---</span>\n`:d}};w.styles=g`
    :host { display: grid; gap: var(--dc-space-4); }

    .cards {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
      gap: var(--dc-space-2);
    }
    .card {
      padding: var(--dc-space-3);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-md);
      background: var(--dc-surface-1);
      cursor: pointer;
      text-align: left;
      letter-spacing: 0.10em;
      font-family: var(--dc-font-mono);
      color: var(--dc-text);
      transition: border-color 0.08s linear;
    }
    .card:hover { border-color: var(--dc-primary); }
    .card.selected {
      border-color: var(--dc-accent);
      background: var(--dc-surface-2);
    }
    .card-name { font-size: var(--dc-fs-md); color: var(--dc-text-bright); }
    .card-sub  { font-size: var(--dc-fs-xs); color: var(--dc-text-faint); margin-top: 2px; }

    .form {
      display: grid;
      gap: var(--dc-space-2);
      padding: var(--dc-space-3);
      border: 1px solid var(--dc-primary);
      border-radius: var(--dc-radius-md);
      background: var(--dc-surface-1);
    }
    .form-row {
      display: grid;
      grid-template-columns: 160px 1fr auto;
      gap: var(--dc-space-2);
      align-items: center;
    }
    label {
      color: var(--dc-text-muted);
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.10em;
      text-transform: uppercase;
    }
    input, select {
      background: var(--dc-bg);
      color: var(--dc-text);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      padding: 6px 10px;
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-md);
      min-width: 0;
    }
    input:focus, select:focus { outline: none; border-color: var(--dc-primary); }

    .flags-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding-top: var(--dc-space-2);
      border-top: 1px dashed var(--dc-border);
    }
    .form-actions {
      display: flex;
      gap: var(--dc-space-2);
      justify-content: flex-end;
      padding-top: var(--dc-space-2);
      border-top: 1px solid var(--dc-border);
    }

    pre {
      margin: 0;
      padding: var(--dc-space-3);
      background: var(--dc-bg);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-md);
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-sm);
      color: var(--dc-text);
      white-space: pre-wrap;
      word-break: break-word;
      max-height: 400px;
      overflow-y: auto;
    }
    .stream-stdout { color: var(--dc-text); }
    .stream-stderr { color: var(--dc-medium); }
    .stream-meta   { color: var(--dc-text-faint); font-style: italic; }
    .stream-exit-ok   { color: var(--dc-clean); font-weight: 700; }
    .stream-exit-fail { color: var(--dc-critical); font-weight: 700; }
    .stream-cancelled { color: var(--dc-quarantine); font-weight: 700; }

    button.action.danger { color: var(--dc-critical); }
    button.action.danger:hover { border-color: var(--dc-critical); }

    .empty {
      padding: var(--dc-space-4);
      border: 1px dashed var(--dc-border);
      border-radius: var(--dc-radius-md);
      color: var(--dc-text-muted);
      font-style: italic;
      text-align: center;
    }
  `;E([l()],w.prototype,"wizards",2);E([l()],w.prototype,"loadError",2);E([l()],w.prototype,"selected",2);E([l()],w.prototype,"positional",2);E([l()],w.prototype,"flags",2);E([l()],w.prototype,"status",2);E([l()],w.prototype,"events",2);w=E([b("dc-setup-wizards")],w);var Ge=Object.defineProperty,Ye=Object.getOwnPropertyDescriptor,Q=(t,e,r,s)=>{for(var a=s>1?void 0:s?Ye(e,r):e,i=t.length-1,o;i>=0;i--)(o=t[i])&&(a=(s?o(e,r,a):o(a))||a);return s&&a&&Ge(e,r,a),a};const Je=["enable","disable","remove","test"];let C=class extends m{constructor(){super(...arguments),this.sinks=[],this.err="",this.busyName="",this.lastResult=null}connectedCallback(){super.connectedCallback(),this.load()}async load(){this.err="";try{const t=await v.get("/v1/sinks");this.sinks=t.sinks??[]}catch(t){const e=t;this.err=e.status?`HTTP ${e.status}`:`failed: ${e.message}`}}async runAction(t,e){if(!(e==="remove"&&!confirm(`Remove sink "${t}"?`))){this.busyName=`${t}:${e}`,this.lastResult=null;try{const r=await v.post(`/v1/sinks/${encodeURIComponent(t)}/${e}`);this.lastResult={name:t,action:e,res:r},await this.load()}catch(r){const s=r;this.lastResult={name:t,action:e,res:{error:s.status?`HTTP ${s.status}: ${this.bodyMsg(s.body)}`:s.message}}}finally{this.busyName=""}}}bodyMsg(t){return t?typeof t=="string"?t:typeof t=="object"&&t&&"error"in t?String(t.error):JSON.stringify(t):""}render(){return n`
      <div class="header">
        <div>
          <div class="dc-section">AUDIT SINKS</div>
          <div class="dc-hint" style="font-size: var(--dc-fs-xs);">
            Configured exporters (splunk_hec / otlp_logs / http_jsonl). Add new with the OBSERVABILITY wizard.
          </div>
        </div>
        <button @click=${()=>void this.load()}>RELOAD</button>
      </div>

      ${this.err?n`<div class="banner err">✗ ${this.err}</div>`:d}
      ${this.renderResult()}

      ${this.sinks.length===0?n`<div class="empty">no sinks configured · run the OBSERVABILITY wizard to add one</div>`:this.renderTable()}
    `}renderTable(){return n`
      <table>
        <thead>
          <tr>
            <th></th>
            <th>Name</th>
            <th>Kind</th>
            <th>Min severity</th>
            <th>Batch / flush / timeout</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          ${this.sinks.map(t=>this.renderRow(t))}
        </tbody>
      </table>
    `}renderRow(t){const e=(t.min_severity??"info").toLowerCase();return n`
      <tr>
        <td>
          <span class="dot" style="color: ${t.enabled?"var(--dc-clean)":"var(--dc-text-faint)"};">
            ${t.enabled?"●":"○"}
          </span>
        </td>
        <td><span class="name">${t.name}</span></td>
        <td><span class="kind">${t.kind}</span></td>
        <td><span class="sev ${e}">${(t.min_severity??"info").toUpperCase()}</span></td>
        <td>
          ${t.batch_size??"—"} · ${t.flush_interval_s??"—"}s · ${t.timeout_s??"—"}s
        </td>
        <td class="actions">
          ${Je.map(r=>{const s=this.busyName===`${t.name}:${r}`,a=!!this.busyName;return n`
              <button
                class="action ${r==="remove"?"danger":""}"
                ?disabled=${a}
                @click=${()=>void this.runAction(t.name,r)}
                title=${r}
              >${s?"…":r.toUpperCase()}</button>
            `})}
        </td>
      </tr>
    `}renderResult(){if(!this.lastResult)return d;const{name:t,action:e,res:r}=this.lastResult;if("error"in r)return n`<div class="banner err">✗ ${t} · ${e} → ${r.error}</div>`;const s=r.ok;return n`
      <div class="banner ${s?"ok":"err"}">
        ${s?"✓":"✗"} ${t} · ${e} → exit ${r.exit_code}
        ${r.output?n`<pre class="output">${r.output}</pre>`:d}
      </div>
    `}};C.styles=g`
    :host { display: grid; gap: var(--dc-space-3); }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: var(--dc-fs-sm);
      background: var(--dc-surface-1);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-md);
      overflow: hidden;
    }
    th, td {
      text-align: left;
      padding: 8px 12px;
      border-bottom: 1px solid var(--dc-border);
      vertical-align: middle;
    }
    th {
      background: var(--dc-surface-2);
      color: var(--dc-text-faint);
      font-weight: 700;
      letter-spacing: 0.10em;
      text-transform: uppercase;
      font-size: var(--dc-fs-xs);
    }
    tr:last-child td { border-bottom: none; }
    td.actions { text-align: right; white-space: nowrap; }

    .name  { font-weight: 700; color: var(--dc-text-bright); }
    .kind  { color: var(--dc-accent); }
    .dot   { display: inline-block; width: 8px; }
    .sev   {
      display: inline-block;
      padding: 1px 6px;
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.06em;
    }
    .sev.critical { color: var(--dc-critical); border-color: var(--dc-critical); }
    .sev.high     { color: var(--dc-high);     border-color: var(--dc-high); }
    .sev.medium   { color: var(--dc-medium);   border-color: var(--dc-medium); }
    .sev.low      { color: var(--dc-low);      border-color: var(--dc-low); }
    .sev.info     { color: var(--dc-info);     border-color: var(--dc-info); }

    button.action {
      padding: 3px 9px;
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.10em;
      margin-left: 4px;
    }
    button.action.danger { color: var(--dc-critical); }
    button.action.danger:hover { border-color: var(--dc-critical); }
    button.action:disabled { opacity: 0.4; cursor: not-allowed; }

    .empty {
      padding: var(--dc-space-4);
      border: 1px dashed var(--dc-border);
      border-radius: var(--dc-radius-md);
      color: var(--dc-text-muted);
      font-style: italic;
      text-align: center;
    }

    .banner {
      padding: var(--dc-space-2) var(--dc-space-3);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      font-size: var(--dc-fs-sm);
    }
    .banner.ok  { border-color: var(--dc-clean);    color: var(--dc-clean); }
    .banner.err { border-color: var(--dc-critical); color: var(--dc-critical); }

    pre.output {
      margin: 4px 0 0 0;
      padding: 8px 10px;
      background: var(--dc-bg);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-xs);
      color: var(--dc-text-muted);
      white-space: pre-wrap;
      word-break: break-word;
      max-height: 200px;
      overflow-y: auto;
    }

    .header {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: var(--dc-space-3);
    }
  `;Q([l()],C.prototype,"sinks",2);Q([l()],C.prototype,"err",2);Q([l()],C.prototype,"busyName",2);Q([l()],C.prototype,"lastResult",2);C=Q([b("dc-sinks")],C);var Ze=Object.defineProperty,Qe=Object.getOwnPropertyDescriptor,X=(t,e,r,s)=>{for(var a=s>1?void 0:s?Qe(e,r):e,i=t.length-1,o;i>=0;i--)(o=t[i])&&(a=(s?o(e,r,a):o(a))||a);return s&&a&&Ze(e,r,a),a};const Xe=["enable","disable","remove","test"];let O=class extends m{constructor(){super(...arguments),this.hooks=[],this.err="",this.busyName="",this.lastResult=null}connectedCallback(){super.connectedCallback(),this.load()}async load(){this.err="";try{const t=await v.get("/v1/webhooks");this.hooks=t.webhooks??[]}catch(t){const e=t;this.err=e.status?`HTTP ${e.status}`:`failed: ${e.message}`}}async runAction(t,e){if(!(e==="remove"&&!confirm(`Remove webhook "${t}"?`))){this.busyName=`${t}:${e}`,this.lastResult=null;try{const r=await v.post(`/v1/webhooks/${encodeURIComponent(t)}/${e}`);this.lastResult={name:t,action:e,res:r},await this.load()}catch(r){const s=r;this.lastResult={name:t,action:e,res:{error:s.status?`HTTP ${s.status}: ${this.bodyMsg(s.body)}`:s.message}}}finally{this.busyName=""}}}bodyMsg(t){return t?typeof t=="string"?t:typeof t=="object"&&t&&"error"in t?String(t.error):JSON.stringify(t):""}render(){return n`
      <div class="header">
        <div>
          <div class="dc-section">WEBHOOKS</div>
          <div class="dc-hint" style="font-size: var(--dc-fs-xs);">
            Slack / PagerDuty / Webex / generic dispatchers. Add new with the WEBHOOK wizard.
          </div>
        </div>
        <button @click=${()=>void this.load()}>RELOAD</button>
      </div>

      ${this.err?n`<div class="banner err">✗ ${this.err}</div>`:d}
      ${this.renderResult()}

      ${this.hooks.length===0?n`<div class="empty">no webhooks configured · run the WEBHOOK wizard to add one</div>`:this.renderTable()}
    `}renderTable(){return n`
      <table>
        <thead>
          <tr>
            <th></th>
            <th>Name</th>
            <th>Type</th>
            <th>URL</th>
            <th>Min severity</th>
            <th>Events</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          ${this.hooks.map(t=>this.renderRow(t))}
        </tbody>
      </table>
    `}renderRow(t){const e=t.name??"(unnamed)",r=(t.min_severity??"info").toLowerCase(),s=t.events&&t.events.length>0?t.events.join(", "):"—";return n`
      <tr>
        <td>
          <span class="dot" style="color: ${t.enabled?"var(--dc-clean)":"var(--dc-text-faint)"};">
            ${t.enabled?"●":"○"}
          </span>
        </td>
        <td><span class="name">${e}</span></td>
        <td><span class="type">${t.type}</span></td>
        <td class="url" title=${t.url}>${t.url}</td>
        <td><span class="sev ${r}">${(t.min_severity??"info").toUpperCase()}</span></td>
        <td class="events">${s}</td>
        <td class="actions">
          ${Xe.map(a=>{const i=this.busyName===`${e}:${a}`,o=!!this.busyName;return n`
              <button
                class="action ${a==="remove"?"danger":""}"
                ?disabled=${o}
                @click=${()=>void this.runAction(e,a)}
                title=${a}
              >${i?"…":a.toUpperCase()}</button>
            `})}
        </td>
      </tr>
    `}renderResult(){if(!this.lastResult)return d;const{name:t,action:e,res:r}=this.lastResult;if("error"in r)return n`<div class="banner err">✗ ${t} · ${e} → ${r.error}</div>`;const s=r.ok;return n`
      <div class="banner ${s?"ok":"err"}">
        ${s?"✓":"✗"} ${t} · ${e} → exit ${r.exit_code}
        ${r.output?n`<pre class="output">${r.output}</pre>`:d}
      </div>
    `}};O.styles=g`
    :host { display: grid; gap: var(--dc-space-3); }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: var(--dc-fs-sm);
      background: var(--dc-surface-1);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-md);
      overflow: hidden;
    }
    th, td {
      text-align: left;
      padding: 8px 12px;
      border-bottom: 1px solid var(--dc-border);
      vertical-align: middle;
    }
    th {
      background: var(--dc-surface-2);
      color: var(--dc-text-faint);
      font-weight: 700;
      letter-spacing: 0.10em;
      text-transform: uppercase;
      font-size: var(--dc-fs-xs);
    }
    tr:last-child td { border-bottom: none; }
    td.actions { text-align: right; white-space: nowrap; }
    td.url {
      max-width: 360px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      color: var(--dc-text-muted);
    }
    td.events {
      color: var(--dc-text-muted);
      font-size: var(--dc-fs-xs);
    }

    .name  { font-weight: 700; color: var(--dc-text-bright); }
    .type  { color: var(--dc-accent); text-transform: uppercase; letter-spacing: 0.06em; }
    .dot   { display: inline-block; width: 8px; }
    .sev   {
      display: inline-block;
      padding: 1px 6px;
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.06em;
    }
    .sev.critical { color: var(--dc-critical); border-color: var(--dc-critical); }
    .sev.high     { color: var(--dc-high);     border-color: var(--dc-high); }
    .sev.medium   { color: var(--dc-medium);   border-color: var(--dc-medium); }
    .sev.low      { color: var(--dc-low);      border-color: var(--dc-low); }
    .sev.info     { color: var(--dc-info);     border-color: var(--dc-info); }

    button.action {
      padding: 3px 9px;
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.10em;
      margin-left: 4px;
    }
    button.action.danger { color: var(--dc-critical); }
    button.action.danger:hover { border-color: var(--dc-critical); }
    button.action:disabled { opacity: 0.4; cursor: not-allowed; }

    .empty {
      padding: var(--dc-space-4);
      border: 1px dashed var(--dc-border);
      border-radius: var(--dc-radius-md);
      color: var(--dc-text-muted);
      font-style: italic;
      text-align: center;
    }

    .banner {
      padding: var(--dc-space-2) var(--dc-space-3);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      font-size: var(--dc-fs-sm);
    }
    .banner.ok  { border-color: var(--dc-clean);    color: var(--dc-clean); }
    .banner.err { border-color: var(--dc-critical); color: var(--dc-critical); }

    pre.output {
      margin: 4px 0 0 0;
      padding: 8px 10px;
      background: var(--dc-bg);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-xs);
      color: var(--dc-text-muted);
      white-space: pre-wrap;
      word-break: break-word;
      max-height: 200px;
      overflow-y: auto;
    }

    .header {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: var(--dc-space-3);
    }
  `;X([l()],O.prototype,"hooks",2);X([l()],O.prototype,"err",2);X([l()],O.prototype,"busyName",2);X([l()],O.prototype,"lastResult",2);O=X([b("dc-webhooks")],O);var tr=Object.defineProperty,er=Object.getOwnPropertyDescriptor,F=(t,e,r,s)=>{for(var a=s>1?void 0:s?er(e,r):e,i=t.length-1,o;i>=0;i--)(o=t[i])&&(a=(s?o(e,r,a):o(a))||a);return s&&a&&tr(e,r,a),a};let k=class extends m{constructor(){super(...arguments),this.status={kind:"idle"},this.text="",this.originalText="",this.path="",this.tab="wizards",this.onInput=t=>{this.text=t.target.value},this.revert=()=>{this.text=this.originalText},this.onTokenSubmit=t=>{t.preventDefault();const s=t.target.elements.namedItem("token")?.value.trim()??"";s&&(Zt(s),this.load())}}connectedCallback(){super.connectedCallback(),this.tab==="config"&&this.load()}switchTab(t){this.tab=t,t==="config"&&this.text===""&&this.load()}async load(){this.status={kind:"loading"};try{const t=await v.get("/v1/config");this.text=t.yaml,this.originalText=t.yaml,this.path=t.path,this.status={kind:"loaded",loadedAt:Date.now()}}catch(t){const e=t;this.status={kind:"error",message:e.status?`GET /v1/config → HTTP ${e.status}: ${this.bodyMessage(e.body)}`:`GET /v1/config failed: ${e.message}`}}}async save(){this.status={kind:"saving"};try{const t=await this.putYaml(this.text);this.originalText=this.text,this.status={kind:"saved",res:t,at:Date.now()}}catch(t){const e=t;this.status={kind:"error",message:e.status?`PUT /v1/config → HTTP ${e.status}: ${this.bodyMessage(e.body)}`:`PUT /v1/config failed: ${e.message}`}}}async putYaml(t){return v.put("/v1/config",{yaml:t})}bodyMessage(t){return t?typeof t=="string"?t:typeof t=="object"&&t&&"error"in t?String(t.error):JSON.stringify(t):"(no body)"}get dirty(){return this.text!==this.originalText}renderTokenPrompt(){return n`
      <div class="banner warn">
        <div>The gateway has token auth enabled. Paste $DEFENSECLAW_GATEWAY_TOKEN below; it'll be stored in localStorage.</div>
        <form
          style="display: flex; gap: var(--dc-space-2); margin-top: var(--dc-space-2);"
          @submit=${this.onTokenSubmit}
        >
          <input
            type="password"
            name="token"
            placeholder="bearer token"
            autocomplete="off"
            spellcheck="false"
            style="flex: 1; min-width: 0; background: var(--dc-bg); color: var(--dc-text); border: 1px solid var(--dc-border); border-radius: var(--dc-radius-sm); padding: 6px 10px; font-family: var(--dc-font-mono); font-size: var(--dc-fs-md);"
          />
          <button type="submit">SAVE TOKEN</button>
        </form>
      </div>
    `}renderRevertBtn(){return this.dirty?n`<button @click=${this.revert} title="Discard local edits">REVERT</button>`:d}render(){return n`
      <div>
        <h1>// SETUP</h1>
        <div class="subtitle dc-hint">
          Run setup wizards or edit ~/.defenseclaw/config.yaml directly. Both write the same file.
        </div>
      </div>

      <div class="tabs">
        <button class="tab ${this.tab==="wizards"?"active":""}" @click=${()=>this.switchTab("wizards")}>WIZARDS</button>
        <button class="tab ${this.tab==="sinks"?"active":""}" @click=${()=>this.switchTab("sinks")}>SINKS</button>
        <button class="tab ${this.tab==="webhooks"?"active":""}" @click=${()=>this.switchTab("webhooks")}>WEBHOOKS</button>
        <button class="tab ${this.tab==="config"?"active":""}" @click=${()=>this.switchTab("config")}>CONFIG EDITOR</button>
      </div>

      ${this.renderTab()}
    `}renderTab(){switch(this.tab){case"wizards":return n`<dc-setup-wizards></dc-setup-wizards>`;case"sinks":return n`<dc-sinks></dc-sinks>`;case"webhooks":return n`<dc-webhooks></dc-webhooks>`;case"config":return this.renderConfigEditor()}}renderConfigEditor(){return n`
      <div class="header">
        <div>
          <div class="dc-section">YAML</div>
          <div class="subtitle dc-hint">Power-user surface — equivalent to the TUI's Config Editor. Wizards write the same file.</div>
        </div>
        <div class="toolbar">
          <span class="meta">${this.path||"—"}</span>
          ${this.dirty?n`<span class="dirty-pip">● modified</span>`:d}
          ${this.renderRevertBtn()}
          <button @click=${()=>void this.load()} ?disabled=${this.status.kind==="loading"||this.status.kind==="saving"}>
            RELOAD
          </button>
          <button @click=${()=>void this.save()} ?disabled=${!this.dirty||this.status.kind==="saving"}>
            SAVE
          </button>
        </div>
      </div>

      ${this.renderBanner()}

      <div class="editor">
        <textarea
          spellcheck="false"
          autocomplete="off"
          autocapitalize="off"
          .value=${this.text}
          @input=${this.onInput}
          ?disabled=${this.status.kind==="loading"}
        ></textarea>
      </div>
    `}renderBanner(){const t=this.status;if(t.kind==="loading")return n`<div class="banner">loading config…</div>`;if(t.kind==="saving")return n`<div class="banner">writing ${this.path}…</div>`;if(t.kind==="error"){const e=t.message.includes("401");return n`
        <div class="banner err">✗ ${t.message}</div>
        ${e?this.renderTokenPrompt():d}
      `}return t.kind==="saved"?n`
        <div class="banner ok">
          ✓ saved → ${t.res.path} · backup at ${t.res.backup}
          ${t.res.needs_restart?.length?n`
            <div class="needs-restart">
              <strong>RESTART REQUIRED FOR:</strong>
              <ul>${t.res.needs_restart.map(e=>n`<li>${e}</li>`)}</ul>
            </div>
          `:d}
        </div>
      `:d}};k.styles=g`
    :host { display: grid; gap: var(--dc-space-4); height: 100%; min-height: 0; }

    .tabs {
      display: flex;
      gap: 0;
      border-bottom: 1px solid var(--dc-border);
    }
    .tab {
      padding: 8px 16px;
      background: transparent;
      border: none;
      border-bottom: 2px solid transparent;
      color: var(--dc-text-muted);
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-sm);
      letter-spacing: 0.14em;
      cursor: pointer;
    }
    .tab:hover { color: var(--dc-text); }
    .tab.active {
      color: var(--dc-accent);
      border-bottom-color: var(--dc-accent);
    }

    .header {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: var(--dc-space-3);
    }
    h1 {
      margin: 0;
      font-size: var(--dc-fs-lg);
      letter-spacing: 0.18em;
      color: var(--dc-text-bright);
      text-transform: uppercase;
    }
    .subtitle {
      color: var(--dc-text-faint);
      font-size: var(--dc-fs-sm);
      letter-spacing: 0.06em;
    }

    .toolbar {
      display: flex;
      gap: var(--dc-space-2);
      align-items: center;
    }
    .toolbar .meta {
      color: var(--dc-text-muted);
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.06em;
    }

    .editor {
      display: grid;
      grid-template-rows: minmax(0, 1fr);
      min-height: 0;
    }
    textarea {
      width: 100%;
      height: 100%;
      min-height: 480px;
      resize: none;
      background: var(--dc-bg);
      color: var(--dc-text);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-md);
      padding: var(--dc-space-3);
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-md);
      line-height: 1.55;
      tab-size: 2;
    }
    textarea:focus {
      outline: none;
      border-color: var(--dc-primary);
    }

    .banner {
      padding: var(--dc-space-2) var(--dc-space-3);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      font-size: var(--dc-fs-sm);
    }
    .banner.ok       { border-color: var(--dc-clean);    color: var(--dc-clean); }
    .banner.warn     { border-color: var(--dc-medium);   color: var(--dc-medium); }
    .banner.err      { border-color: var(--dc-critical); color: var(--dc-critical); }

    .needs-restart {
      margin-top: var(--dc-space-1);
      color: var(--dc-medium);
      font-size: var(--dc-fs-xs);
    }
    .needs-restart ul { margin: 4px 0 0 18px; padding: 0; }

    .dirty-pip {
      color: var(--dc-medium);
      font-style: italic;
    }
  `;F([l()],k.prototype,"status",2);F([l()],k.prototype,"text",2);F([l()],k.prototype,"originalText",2);F([l()],k.prototype,"path",2);F([l()],k.prototype,"tab",2);k=F([b("dc-setup")],k);const Ht={INFO:0,LOW:1,MEDIUM:2,HIGH:3,CRITICAL:4},rr=["!=",">=","<=","=",":"];function Xt(t){const e=t.trim().split(/\s+/).filter(Boolean),r=[];for(const s of e){let a=null;for(const i of rr){const o=s.indexOf(i);if(o>0){a={key:s.slice(0,o).toLowerCase(),op:i,value:s.slice(o+i.length)};break}}r.push(a??{key:null,op:":",value:s})}return r}function te(t,e){return e.length===0?t:t.filter(r=>e.every(s=>sr(r,s)))}function sr(t,e){if(e.key===null)return`${t.action} ${t.target} ${t.actor} ${t.details} ${t.severity} ${t.run_id??""} ${t.trace_id??""} ${t.policy_id??""} ${t.tool_name??""}`.toLowerCase().includes(e.value.toLowerCase());if(e.key==="severity"&&(e.op===">="||e.op==="<=")){const s=Ht[(t.severity??"").toUpperCase()]??0,a=Ht[e.value.toUpperCase()]??0;return e.op===">="?s>=a:s<=a}if(e.key.endsWith("_contains")){const s=e.key.slice(0,-9);return String(t[s]??"").toLowerCase().includes(e.value.toLowerCase())}const r=String(t[e.key]??"");switch(e.op){case"=":case":":return r.toLowerCase()===e.value.toLowerCase();case"!=":return r.toLowerCase()!==e.value.toLowerCase();case">=":case"<=":return!1}}var ar=Object.defineProperty,ir=Object.getOwnPropertyDescriptor,At=(t,e,r,s)=>{for(var a=s>1?void 0:s?ir(e,r):e,i=t.length-1,o;i>=0;i--)(o=t[i])&&(a=(s?o(e,r,a):o(a))||a);return s&&a&&ar(e,r,a),a};const or={CRITICAL:"critical",HIGH:"high",MEDIUM:"medium",LOW:"low",INFO:"info"};let J=class extends m{constructor(){super(...arguments),this.filterText="",this.selectedID=null,this.poll=new x(this,()=>v.get("/v1/audit?limit=500"),5e3),this.onFilterInput=t=>{this.filterText=t.target.value}}get events(){return this.poll.state.value?.events??[]}get filtered(){const t=Xt(this.filterText);return te(this.events,t)}select(t){this.selectedID=this.selectedID===t?null:t}get selected(){return this.selectedID?this.events.find(t=>t.id===this.selectedID)??null:null}render(){return n`
      <div class="header">
        <div>
          <h1>// AUDIT</h1>
          <div class="subtitle dc-hint">
            Append-only evidence trail. Compound filter syntax: <code>action=verdict severity>=high actor=remo</code>
          </div>
        </div>
        <div class="stats">
          showing ${this.filtered.length} of ${this.events.length}
          ${this.poll.state.freshness==="stale"?n` · <span style="color: var(--dc-medium);">stale</span>`:d}
        </div>
      </div>

      ${this.poll.state.error?n`<div class="err">✗ ${this.poll.state.error.message}</div>`:d}

      <div class="filter-bar">
        <input
          type="text"
          placeholder="action=verdict severity>=high target_contains=github  (or bare keyword)"
          .value=${this.filterText}
          @input=${this.onFilterInput}
        />
        <button @click=${()=>{this.filterText=""}}>CLEAR</button>
        <button @click=${()=>void this.poll.refresh()}>RELOAD</button>
      </div>

      <div class="body">
        <div class="table-wrap">
          ${this.renderTable()}
        </div>
        <aside class="detail">
          ${this.renderDetail()}
        </aside>
      </div>
    `}renderTable(){const t=this.filtered;return t.length===0?n`<div class="empty">no rows match · clear the filter to widen</div>`:n`
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Severity</th>
            <th>Action</th>
            <th>Target</th>
            <th>Actor</th>
            <th>Run</th>
          </tr>
        </thead>
        <tbody>
          ${t.map(e=>{const r=(e.severity??"INFO").toUpperCase(),s=or[r]??"info",a=new Date(e.timestamp).toLocaleTimeString();return n`
              <tr class="row ${this.selectedID===e.id?"sel":""}" @click=${()=>this.select(e.id)}>
                <td>${a}</td>
                <td><span class="sev ${s}">${r}</span></td>
                <td>${e.action}</td>
                <td class="target" title=${e.target}>${e.target||"—"}</td>
                <td>${e.actor||"—"}</td>
                <td>${e.run_id??"—"}</td>
              </tr>
            `})}
        </tbody>
      </table>
    `}renderDetail(){const t=this.selected;if(!t)return n`<div class="empty">click a row to inspect</div>`;const e=[["id",t.id],["timestamp",t.timestamp],["action",t.action],["severity",t.severity??"—"],["target",t.target||"—"],["actor",t.actor||"—"],["run_id",t.run_id??"—"],["trace_id",t.trace_id??"—"],["request_id",t.request_id??"—"],["session_id",t.session_id??"—"],["agent_name",t.agent_name??"—"],["policy_id",t.policy_id??"—"],["destination_app",t.destination_app??"—"],["tool_name",t.tool_name??"—"]];return n`
      <h3>EVIDENCE</h3>
      <dl>
        ${e.map(([r,s])=>n`<dt>${r}</dt><dd>${s}</dd>`)}
      </dl>
      ${t.details?n`<div class="details-blob">${t.details}</div>`:d}
    `}};J.styles=g`
    :host { display: grid; grid-template-rows: auto auto minmax(0,1fr); gap: var(--dc-space-3); height: 100%; min-height: 0; }

    .header {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: var(--dc-space-3);
    }
    h1 {
      margin: 0;
      font-size: var(--dc-fs-lg);
      letter-spacing: 0.18em;
      color: var(--dc-text-bright);
      text-transform: uppercase;
    }
    .subtitle { color: var(--dc-text-faint); font-size: var(--dc-fs-sm); }

    .filter-bar {
      display: grid;
      grid-template-columns: 1fr auto auto;
      gap: var(--dc-space-2);
      align-items: center;
      padding: var(--dc-space-2) var(--dc-space-3);
      background: var(--dc-surface-1);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-md);
    }
    input {
      background: var(--dc-bg);
      color: var(--dc-text);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      padding: 6px 10px;
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-md);
    }
    input:focus { outline: none; border-color: var(--dc-primary); }

    .stats {
      color: var(--dc-text-muted);
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.06em;
    }

    .body {
      display: grid;
      grid-template-columns: minmax(0, 1fr) 380px;
      gap: var(--dc-space-3);
      min-height: 0;
    }
    .table-wrap, .detail {
      overflow: auto;
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-md);
      background: var(--dc-surface-1);
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: var(--dc-fs-sm);
    }
    thead { position: sticky; top: 0; z-index: 1; }
    th, td {
      text-align: left;
      padding: 6px 10px;
      border-bottom: 1px solid var(--dc-border);
      white-space: nowrap;
    }
    th {
      background: var(--dc-surface-2);
      color: var(--dc-text-faint);
      font-weight: 700;
      letter-spacing: 0.10em;
      text-transform: uppercase;
      font-size: var(--dc-fs-xs);
    }
    tr.sel td { background: var(--dc-row-selected); }
    tr.row { cursor: pointer; }
    tr.row:hover td { background: var(--dc-row-hover); }
    td.target {
      max-width: 280px;
      overflow: hidden;
      text-overflow: ellipsis;
      color: var(--dc-text);
    }

    .sev {
      display: inline-block;
      padding: 1px 6px;
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.06em;
    }
    .sev.critical { color: var(--dc-critical); border-color: var(--dc-critical); }
    .sev.high     { color: var(--dc-high);     border-color: var(--dc-high); }
    .sev.medium   { color: var(--dc-medium);   border-color: var(--dc-medium); }
    .sev.low      { color: var(--dc-low);      border-color: var(--dc-low); }
    .sev.info     { color: var(--dc-info);     border-color: var(--dc-info); }

    .detail {
      padding: var(--dc-space-3);
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-sm);
    }
    .detail h3 {
      margin: 0 0 var(--dc-space-2) 0;
      color: var(--dc-accent);
      letter-spacing: 0.14em;
      text-transform: uppercase;
      font-size: var(--dc-fs-md);
    }
    .detail dl { margin: 0; display: grid; grid-template-columns: 110px 1fr; gap: 4px 8px; }
    .detail dt { color: var(--dc-text-faint); font-size: var(--dc-fs-xs); text-transform: uppercase; letter-spacing: 0.10em; }
    .detail dd { margin: 0; color: var(--dc-text); word-break: break-word; }
    .detail .details-blob {
      margin-top: var(--dc-space-3);
      padding: var(--dc-space-2);
      background: var(--dc-bg);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      white-space: pre-wrap;
      word-break: break-word;
      font-size: var(--dc-fs-xs);
      color: var(--dc-text-muted);
    }

    .empty {
      padding: var(--dc-space-5);
      color: var(--dc-text-muted);
      font-style: italic;
      text-align: center;
    }

    .err {
      padding: var(--dc-space-2) var(--dc-space-3);
      border: 1px solid var(--dc-critical);
      border-radius: var(--dc-radius-sm);
      color: var(--dc-critical);
      font-size: var(--dc-fs-sm);
    }
  `;At([l()],J.prototype,"filterText",2);At([l()],J.prototype,"selectedID",2);J=At([b("dc-audit")],J);var nr=Object.defineProperty,dr=Object.getOwnPropertyDescriptor,ht=(t,e,r,s)=>{for(var a=s>1?void 0:s?dr(e,r):e,i=t.length-1,o;i>=0;i--)(o=t[i])&&(a=(s?o(e,r,a):o(a))||a);return s&&a&&nr(e,r,a),a};let M=class extends m{constructor(){super(...arguments),this.filterText="",this.follow=!0,this.autoScrollDirty=!1,this.poll=new x(this,()=>v.get("/v1/logs?tail=500"),2e3),this.onScroll=t=>{const e=t.target,r=e.scrollHeight-e.scrollTop-e.clientHeight<20;this.autoScrollDirty=!r}}updated(){if(this.follow&&!this.autoScrollDirty){const t=this.renderRoot?.querySelector(".pane");t&&(t.scrollTop=t.scrollHeight)}}render(){const t=this.poll.state.value,e=this.poll.state.error;return n`
      <div class="header">
        <div>
          <h1>// LOGS</h1>
          <div class="subtitle dc-hint">Tail of ${t?.path??"~/.defenseclaw/gateway.log"}</div>
        </div>
        <div class="meta">
          ${t?`${t.lines.length} lines · ${cr(t.size)}`:"loading…"}
          ${this.poll.state.freshness==="stale"?n` · <span style="color: var(--dc-medium);">stale</span>`:d}
        </div>
      </div>

      ${e?n`<div class="err">✗ ${e.message}</div>`:d}

      <div class="toolbar">
        <input
          type="text"
          placeholder="filter (substring)…"
          .value=${this.filterText}
          @input=${r=>{this.filterText=r.target.value}}
        />
        <label class="meta" style="display: inline-flex; align-items: center; gap: 4px;">
          <input
            type="checkbox"
            .checked=${this.follow}
            @change=${r=>{this.follow=r.target.checked}}
            style="width: auto; padding: 0;"
          />
          FOLLOW
        </label>
        <button @click=${()=>{this.filterText=""}}>CLEAR</button>
        <button @click=${()=>void this.poll.refresh()}>RELOAD</button>
      </div>

      <div class="pane" @scroll=${this.onScroll}>
        ${this.renderLines(t?.lines??[])}
      </div>
    `}renderLines(t){if(t.length===0)return n`<div class="empty">no log lines yet</div>`;const e=this.filterText.trim().toLowerCase();return n`
      <pre>${t.map(r=>{const s=r.toLowerCase();if(e&&!s.includes(e))return d;let a="line";return s.includes("error")||s.includes("[err]")?a+=" error":s.includes("warn")&&(a+=" warn"),e&&s.includes(e)&&(a+=" match"),n`<span class=${a}>${r}\n</span>`})}</pre>
    `}};M.styles=g`
    :host { display: grid; grid-template-rows: auto auto minmax(0, 1fr); gap: var(--dc-space-3); height: 100%; min-height: 0; }

    .header {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: var(--dc-space-3);
    }
    h1 {
      margin: 0;
      font-size: var(--dc-fs-lg);
      letter-spacing: 0.18em;
      color: var(--dc-text-bright);
      text-transform: uppercase;
    }
    .subtitle { color: var(--dc-text-faint); font-size: var(--dc-fs-sm); }

    .toolbar {
      display: grid;
      grid-template-columns: 1fr auto auto auto;
      gap: var(--dc-space-2);
      align-items: center;
      padding: var(--dc-space-2) var(--dc-space-3);
      background: var(--dc-surface-1);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-md);
    }
    input {
      background: var(--dc-bg);
      color: var(--dc-text);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      padding: 6px 10px;
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-md);
    }
    input:focus { outline: none; border-color: var(--dc-primary); }
    .meta {
      color: var(--dc-text-muted);
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.06em;
    }

    .pane {
      overflow: auto;
      background: var(--dc-bg);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-md);
    }
    .pane pre {
      margin: 0;
      padding: var(--dc-space-3);
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-xs);
      color: var(--dc-text);
      white-space: pre;
    }

    .line { display: block; }
    .line.match { background: rgba(95, 95, 215, 0.18); }
    .line.error { color: var(--dc-critical); }
    .line.warn  { color: var(--dc-medium); }

    .empty {
      padding: var(--dc-space-5);
      color: var(--dc-text-muted);
      font-style: italic;
      text-align: center;
    }
    .err {
      padding: var(--dc-space-2) var(--dc-space-3);
      border: 1px solid var(--dc-critical);
      border-radius: var(--dc-radius-sm);
      color: var(--dc-critical);
      font-size: var(--dc-fs-sm);
    }
  `;ht([l()],M.prototype,"filterText",2);ht([l()],M.prototype,"follow",2);ht([l()],M.prototype,"autoScrollDirty",2);M=ht([b("dc-logs")],M);function cr(t){return t<1024?`${t} B`:t<1024*1024?`${(t/1024).toFixed(1)} KB`:t<1024*1024*1024?`${(t/1024/1024).toFixed(1)} MB`:`${(t/1024/1024/1024).toFixed(2)} GB`}var lr=Object.defineProperty,pr=Object.getOwnPropertyDescriptor,tt=(t,e,r,s)=>{for(var a=s>1?void 0:s?pr(e,r):e,i=t.length-1,o;i>=0;i--)(o=t[i])&&(a=(s?o(e,r,a):o(a))||a);return s&&a&&lr(e,r,a),a};const hr={skill:["scan","allow","block","quarantine","restore","disable","enable"],mcp:["scan","allow","block","quarantine","restore","disable","enable"],plugin:["scan","install","disable","enable"],tool:[]},Ft=new Set(["block","quarantine","remove"]),ur=[{id:"all",label:"ALL"},{id:"skills",label:"SKILLS"},{id:"mcps",label:"MCPS"},{id:"plugins",label:"PLUGINS"},{id:"tools",label:"TOOLS"}];let z=class extends m{constructor(){super(...arguments),this.scope="all",this.filterText="",this.busyKey="",this.lastResult=null,this.skills=new x(this,()=>v.get("/skills"),3e4),this.mcps=new x(this,()=>v.get("/mcps"),3e4),this.plugins=new x(this,()=>v.get("/v1/plugins"),3e4),this.tools=new x(this,()=>v.get("/tools/catalog"),3e4)}async runAction(t,e,r){if(Ft.has(r)&&!confirm(`${r.toUpperCase()} ${t} "${e}"?`))return;const s=`/v1/${t}s/${encodeURIComponent(e)}/${r}`;this.busyKey=`${t}:${e}:${r}`,this.lastResult=null;try{const a=await v.post(s);this.lastResult={kind:t,name:e,action:r,res:a},t==="skill"&&this.skills.refresh(),t==="mcp"&&this.mcps.refresh(),t==="plugin"&&this.plugins.refresh()}catch(a){const i=a;this.lastResult={kind:t,name:e,action:r,res:{error:i.status?`HTTP ${i.status}`:i.message}}}finally{this.busyKey=""}}get rows(){const t=[],e=this.skills.state.value?.skills??[];for(const i of e){const o=i.name??i.key??"(unnamed)";t.push({kind:"skill",name:String(o),status:i.quarantined?"quarantined":i.verdict??i.trust??"—",detail:ft(i,["source","version","verdict_severity"]),raw:i})}const r=this.mcps.state.value?.mcps??this.mcps.state.value?.servers??[];for(const i of r)t.push({kind:"mcp",name:i.name,status:i.allowed===!1?"blocked":i.transport??"—",detail:i.url??ft(i,["command","transport"]),raw:i});const s=this.plugins.state.value?.plugins??[];for(const i of s)t.push({kind:"plugin",name:i.name,status:i.has_manifest?"manifest":"—",detail:i.path,raw:i});const a=this.tools.state.value?.tools??this.tools.state.value?.catalog??[];for(const i of a){const o=i.tool_name??i.name??"(unnamed)";t.push({kind:"tool",name:String(o),status:String(i.mcp??i.server??"—"),detail:ft(i,["description","summary"]),raw:i})}return t}get visible(){let t=this.rows;if(this.scope!=="all"){const e=this.scope.replace(/s$/,"");t=t.filter(r=>r.kind===e)}if(this.filterText.trim()){const e=this.filterText.trim().toLowerCase();t=t.filter(r=>r.name.toLowerCase().includes(e)||r.status.toLowerCase().includes(e)||r.detail.toLowerCase().includes(e))}return t}get countsByKind(){const t={skill:0,mcp:0,plugin:0,tool:0};for(const e of this.rows)t[e.kind]++;return t}render(){const t=this.countsByKind,e=this.rows.length;return n`
      <div class="header">
        <div>
          <h1>// INVENTORY</h1>
          <div class="subtitle dc-hint">
            Skills + MCP servers + plugins + tools, unified. Filter by scope chip or substring search.
          </div>
        </div>
        <div class="stats">
          ${t.skill} skills · ${t.mcp} mcps · ${t.plugin} plugins · ${t.tool} tools
        </div>
      </div>

      <div class="scope-bar">
        ${ur.map(r=>{const s=r.id==="all"?e:t[r.id.replace(/s$/,"")]??0;return n`
            <button
              class="chip ${this.scope===r.id?"active":""}"
              @click=${()=>{this.scope=r.id}}
            >${r.label} · ${s}</button>
          `})}
      </div>

      <div class="filter-bar">
        <input
          type="text"
          placeholder="filter by name, status, or detail…"
          .value=${this.filterText}
          @input=${r=>{this.filterText=r.target.value}}
        />
        <button @click=${()=>{this.filterText=""}}>CLEAR</button>
      </div>

      ${this.renderResultBanner()}
      <div class="table-wrap">${this.renderTable()}</div>
    `}renderResultBanner(){if(!this.lastResult)return d;const{kind:t,name:e,action:r,res:s}=this.lastResult;if("error"in s)return n`<div class="banner err">✗ ${t} ${e} · ${r} → ${s.error}</div>`;const a=s.ok;return n`
      <div class="banner ${a?"ok":"err"}">
        ${a?"✓":"✗"} ${t} ${e} · ${r} → exit ${s.exit_code}
        ${s.output?n`<pre class="output">${s.output}</pre>`:d}
      </div>
    `}renderTable(){const t=this.visible;return t.length===0?n`<div class="empty">no items match · widen the scope or clear the filter</div>`:n`
      <table>
        <thead>
          <tr><th>Kind</th><th>Name</th><th>Status</th><th>Detail</th><th>Actions</th></tr>
        </thead>
        <tbody>
          ${t.map(e=>n`
            <tr>
              <td class="kind">${e.kind}</td>
              <td class="name">${e.name}</td>
              <td>${e.status}</td>
              <td class="detail" title=${e.detail}>${e.detail}</td>
              <td class="actions">${this.renderActions(e.kind,e.name)}</td>
            </tr>
          `)}
        </tbody>
      </table>
    `}renderActions(t,e){const r=hr[t]??[];if(r.length===0)return n`<span style="color: var(--dc-text-faint); font-style: italic; font-size: var(--dc-fs-xs);">—</span>`;const s=!!this.busyKey;return r.map(a=>{const i=this.busyKey===`${t}:${e}:${a}`,o=Ft.has(a);return n`
        <button
          class="action ${o?"danger":""}"
          ?disabled=${s}
          @click=${()=>void this.runAction(t,e,a)}
          title=${a}
        >${i?"…":a.toUpperCase()}</button>
      `})}};z.styles=g`
    :host { display: grid; grid-template-rows: auto auto auto minmax(0,1fr); gap: var(--dc-space-3); height: 100%; min-height: 0; }

    .header {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: var(--dc-space-3);
    }
    h1 {
      margin: 0;
      font-size: var(--dc-fs-lg);
      letter-spacing: 0.18em;
      color: var(--dc-text-bright);
      text-transform: uppercase;
    }
    .subtitle { color: var(--dc-text-faint); font-size: var(--dc-fs-sm); }

    .scope-bar {
      display: flex;
      gap: var(--dc-space-2);
      align-items: center;
      flex-wrap: wrap;
    }
    .chip {
      padding: 4px 12px;
      background: transparent;
      color: var(--dc-text-muted);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.10em;
      cursor: pointer;
    }
    .chip:hover { color: var(--dc-text); border-color: var(--dc-primary); }
    .chip.active {
      color: var(--dc-text-bright);
      background: var(--dc-surface-2);
      border-color: var(--dc-accent);
    }

    .filter-bar {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: var(--dc-space-2);
      align-items: center;
      padding: var(--dc-space-2) var(--dc-space-3);
      background: var(--dc-surface-1);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-md);
    }
    input {
      background: var(--dc-bg);
      color: var(--dc-text);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      padding: 6px 10px;
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-md);
    }
    input:focus { outline: none; border-color: var(--dc-primary); }

    .table-wrap {
      overflow: auto;
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-md);
      background: var(--dc-surface-1);
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: var(--dc-fs-sm);
    }
    thead { position: sticky; top: 0; z-index: 1; }
    th, td {
      text-align: left;
      padding: 6px 10px;
      border-bottom: 1px solid var(--dc-border);
    }
    th {
      background: var(--dc-surface-2);
      color: var(--dc-text-faint);
      font-weight: 700;
      letter-spacing: 0.10em;
      text-transform: uppercase;
      font-size: var(--dc-fs-xs);
    }
    td.kind {
      color: var(--dc-accent);
      letter-spacing: 0.10em;
      text-transform: uppercase;
      font-size: var(--dc-fs-xs);
    }
    td.name { color: var(--dc-text-bright); font-weight: 700; }
    td.detail { color: var(--dc-text-muted); font-size: var(--dc-fs-xs); }
    td.actions { white-space: nowrap; text-align: right; }
    .stats { color: var(--dc-text-muted); font-size: var(--dc-fs-xs); letter-spacing: 0.06em; }

    button.action {
      padding: 3px 9px;
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.08em;
      margin-left: 4px;
    }
    button.action.danger { color: var(--dc-critical); }
    button.action.danger:hover { border-color: var(--dc-critical); }
    button.action:disabled { opacity: 0.4; cursor: not-allowed; }

    .banner {
      padding: var(--dc-space-2) var(--dc-space-3);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      font-size: var(--dc-fs-sm);
      margin-bottom: var(--dc-space-2);
    }
    .banner.ok  { border-color: var(--dc-clean);    color: var(--dc-clean); }
    .banner.err { border-color: var(--dc-critical); color: var(--dc-critical); }
    pre.output {
      margin: 4px 0 0 0;
      padding: 8px 10px;
      background: var(--dc-bg);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-xs);
      color: var(--dc-text-muted);
      white-space: pre-wrap;
      word-break: break-word;
      max-height: 200px;
      overflow-y: auto;
    }

    .empty {
      padding: var(--dc-space-5);
      color: var(--dc-text-muted);
      font-style: italic;
      text-align: center;
    }
  `;tt([l()],z.prototype,"scope",2);tt([l()],z.prototype,"filterText",2);tt([l()],z.prototype,"busyKey",2);tt([l()],z.prototype,"lastResult",2);z=tt([b("dc-inventory")],z);function ft(t,e){for(const r of e){const s=t[r];if(s!=null&&s!=="")return String(s)}return"—"}var vr=Object.defineProperty,fr=Object.getOwnPropertyDescriptor,ut=(t,e,r,s)=>{for(var a=s>1?void 0:s?fr(e,r):e,i=t.length-1,o;i>=0;i--)(o=t[i])&&(a=(s?o(e,r,a):o(a))||a);return s&&a&&vr(e,r,a),a};const mr={CRITICAL:"critical",HIGH:"high",MEDIUM:"medium",LOW:"low",INFO:"info"};let j=class extends m{constructor(){super(...arguments),this.filterText="",this.actionFilter="",this.selectedID=null,this.poll=new x(this,()=>v.get("/alerts?limit=500"),5e3)}get events(){return this.poll.state.value??[]}get filtered(){const t=Xt(this.filterText);let e=te(this.events,t);return this.actionFilter&&(e=e.filter(r=>Bt(r)===this.actionFilter)),e}get selected(){return this.selectedID?this.events.find(t=>t.id===this.selectedID)??null:null}render(){return n`
      <div class="header">
        <div>
          <h1>// ALERTS</h1>
          <div class="subtitle dc-hint">
            Active findings from the audit store. Filter syntax: <code>severity>=high action=verdict actor=remo</code>
          </div>
        </div>
        <div class="stats">
          showing ${this.filtered.length} of ${this.events.length}
          ${this.poll.state.freshness==="stale"?n` · <span style="color: var(--dc-medium);">stale</span>`:d}
        </div>
      </div>

      ${this.poll.state.error?n`<div class="err">✗ ${this.poll.state.error.message}</div>`:d}

      <div class="filter-bar">
        <input
          type="text"
          placeholder="severity>=high action=verdict target_contains=mcp  (or bare keyword)"
          .value=${this.filterText}
          @input=${t=>{this.filterText=t.target.value}}
        />
        <button @click=${()=>{this.filterText="",this.actionFilter=""}}>CLEAR</button>
        <button @click=${()=>void this.poll.refresh()}>RELOAD</button>
      </div>

      <div class="chips">
        ${["","block","warn","allow"].map(t=>n`
          <button
            class="chip ${this.actionFilter===t?"active":""}"
            @click=${()=>{this.actionFilter=t}}
          >${t===""?"ALL":t.toUpperCase()}</button>
        `)}
      </div>

      <div class="body">
        <div class="table-wrap">${this.renderTable()}</div>
        <aside class="detail">${this.renderDetail()}</aside>
      </div>
    `}renderTable(){const t=this.filtered;return t.length===0?n`<div class="empty">no alerts match · clear filters to widen</div>`:n`
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Severity</th>
            <th>Action</th>
            <th>Verdict</th>
            <th>Target</th>
            <th>Actor</th>
          </tr>
        </thead>
        <tbody>
          ${t.map(e=>{const r=(e.severity??"INFO").toUpperCase(),s=mr[r]??"info",a=Bt(e),i=new Date(e.timestamp).toLocaleTimeString();return n`
              <tr class="row ${this.selectedID===e.id?"sel":""}" @click=${()=>{this.selectedID=this.selectedID===e.id?null:e.id}}>
                <td>${i}</td>
                <td><span class="sev ${s}">${r}</span></td>
                <td class="action">${e.action}</td>
                <td><span class="verdict ${a??"other"}">${a??"—"}</span></td>
                <td class="target" title=${e.target}>${e.target||"—"}</td>
                <td>${e.actor||"—"}</td>
              </tr>
            `})}
        </tbody>
      </table>
    `}renderDetail(){const t=this.selected;if(!t)return n`<div class="empty">click a row to inspect</div>`;const e=[["id",t.id],["timestamp",t.timestamp],["action",t.action],["severity",t.severity??"—"],["target",t.target||"—"],["actor",t.actor||"—"],["run_id",t.run_id??"—"],["trace_id",t.trace_id??"—"],["request_id",t.request_id??"—"],["session_id",t.session_id??"—"],["policy_id",t.policy_id??"—"],["tool_name",t.tool_name??"—"]];return n`
      <h3>EVIDENCE</h3>
      <dl>${e.map(([r,s])=>n`<dt>${r}</dt><dd>${s}</dd>`)}</dl>
      ${t.details?n`<div class="blob">${t.details}</div>`:d}
    `}};j.styles=g`
    :host { display: grid; grid-template-rows: auto auto auto minmax(0,1fr); gap: var(--dc-space-3); height: 100%; min-height: 0; }

    .header {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: var(--dc-space-3);
    }
    h1 {
      margin: 0;
      font-size: var(--dc-fs-lg);
      letter-spacing: 0.18em;
      color: var(--dc-text-bright);
      text-transform: uppercase;
    }
    .subtitle { color: var(--dc-text-faint); font-size: var(--dc-fs-sm); }
    .stats { color: var(--dc-text-muted); font-size: var(--dc-fs-xs); letter-spacing: 0.06em; }

    .filter-bar {
      display: grid;
      grid-template-columns: 1fr auto auto;
      gap: var(--dc-space-2);
      align-items: center;
      padding: var(--dc-space-2) var(--dc-space-3);
      background: var(--dc-surface-1);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-md);
    }
    input {
      background: var(--dc-bg);
      color: var(--dc-text);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      padding: 6px 10px;
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-md);
    }
    input:focus { outline: none; border-color: var(--dc-primary); }

    .chips {
      display: flex;
      gap: var(--dc-space-2);
      align-items: center;
      flex-wrap: wrap;
    }
    .chip {
      padding: 3px 10px;
      background: transparent;
      color: var(--dc-text-muted);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.10em;
      cursor: pointer;
    }
    .chip:hover { color: var(--dc-text); border-color: var(--dc-primary); }
    .chip.active {
      color: var(--dc-text-bright);
      background: var(--dc-surface-2);
      border-color: var(--dc-accent);
    }

    .body {
      display: grid;
      grid-template-columns: minmax(0, 1fr) 380px;
      gap: var(--dc-space-3);
      min-height: 0;
    }
    .table-wrap, .detail {
      overflow: auto;
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-md);
      background: var(--dc-surface-1);
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: var(--dc-fs-sm);
    }
    thead { position: sticky; top: 0; z-index: 1; }
    th, td {
      text-align: left;
      padding: 6px 10px;
      border-bottom: 1px solid var(--dc-border);
      white-space: nowrap;
    }
    th {
      background: var(--dc-surface-2);
      color: var(--dc-text-faint);
      font-weight: 700;
      letter-spacing: 0.10em;
      text-transform: uppercase;
      font-size: var(--dc-fs-xs);
    }
    tr.sel td { background: var(--dc-row-selected); }
    tr.row { cursor: pointer; }
    tr.row:hover td { background: var(--dc-row-hover); }
    td.target { max-width: 280px; overflow: hidden; text-overflow: ellipsis; }
    td.action { color: var(--dc-text); }

    .sev {
      display: inline-block;
      padding: 1px 6px;
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.06em;
    }
    .sev.critical { color: var(--dc-critical); border-color: var(--dc-critical); }
    .sev.high     { color: var(--dc-high);     border-color: var(--dc-high); }
    .sev.medium   { color: var(--dc-medium);   border-color: var(--dc-medium); }
    .sev.low      { color: var(--dc-low);      border-color: var(--dc-low); }
    .sev.info     { color: var(--dc-info);     border-color: var(--dc-info); }

    .verdict {
      display: inline-block;
      padding: 1px 6px;
      border-radius: var(--dc-radius-sm);
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.06em;
      text-transform: lowercase;
    }
    .verdict.block { color: var(--dc-critical); border: 1px solid var(--dc-critical); }
    .verdict.warn  { color: var(--dc-medium);   border: 1px solid var(--dc-medium); }
    .verdict.allow { color: var(--dc-clean);    border: 1px solid var(--dc-clean); }
    .verdict.other { color: var(--dc-text-muted); border: 1px solid var(--dc-border); }

    .detail {
      padding: var(--dc-space-3);
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-sm);
    }
    .detail h3 {
      margin: 0 0 var(--dc-space-2) 0;
      color: var(--dc-accent);
      letter-spacing: 0.14em;
      text-transform: uppercase;
      font-size: var(--dc-fs-md);
    }
    .detail dl { margin: 0; display: grid; grid-template-columns: 110px 1fr; gap: 4px 8px; }
    .detail dt { color: var(--dc-text-faint); font-size: var(--dc-fs-xs); text-transform: uppercase; letter-spacing: 0.10em; }
    .detail dd { margin: 0; color: var(--dc-text); word-break: break-word; }
    .detail .blob {
      margin-top: var(--dc-space-3);
      padding: var(--dc-space-2);
      background: var(--dc-bg);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-sm);
      white-space: pre-wrap;
      word-break: break-word;
      font-size: var(--dc-fs-xs);
      color: var(--dc-text-muted);
    }

    .empty {
      padding: var(--dc-space-5);
      color: var(--dc-text-muted);
      font-style: italic;
      text-align: center;
    }
    .err {
      padding: var(--dc-space-2) var(--dc-space-3);
      border: 1px solid var(--dc-critical);
      border-radius: var(--dc-radius-sm);
      color: var(--dc-critical);
      font-size: var(--dc-fs-sm);
    }
  `;ut([l()],j.prototype,"filterText",2);ut([l()],j.prototype,"actionFilter",2);ut([l()],j.prototype,"selectedID",2);j=ut([b("dc-alerts")],j);function Bt(t){const e=`${t.action} ${t.details}`.toLowerCase();return/\b(block|blocked|deny|denied|reject|rejected)\b/.test(e)?"block":/\b(warn|warning|alert|alerted|review)\b/.test(e)?"warn":/\b(allow|allowed|pass|passed|clean)\b/.test(e)?"allow":null}var gr=Object.defineProperty,br=Object.getOwnPropertyDescriptor,et=(t,e,r,s)=>{for(var a=s>1?void 0:s?br(e,r):e,i=t.length-1,o;i>=0;i--)(o=t[i])&&(a=(s?o(e,r,a):o(a))||a);return s&&a&&gr(e,r,a),a};const $r=["rego","guardrail-rule","suppression","scanner","data","yaml","other"],yr={rego:"REGO MODULES","guardrail-rule":"GUARDRAIL RULES",suppression:"SUPPRESSIONS",scanner:"SCANNER REGISTRATIONS",data:"DATA OVERLAYS",yaml:"YAML",other:"OTHER"};let P=class extends m{constructor(){super(...arguments),this.selectedPath=null,this.content=null,this.contentErr="",this.contentLoading=!1,this.listPoll=new x(this,()=>v.get("/v1/policy/bundles"),3e4)}async loadContent(t){this.contentLoading=!0,this.contentErr="",this.content=null;try{const e=await v.get(`/v1/policy/bundle?path=${encodeURIComponent(t)}`);this.content=e}catch(e){this.contentErr=e.message}finally{this.contentLoading=!1}}select(t){this.selectedPath=t,this.loadContent(t)}render(){const t=this.listPoll.state.value,e=this.listPoll.state.error,r=t?.bundles??[],s=xr(r,a=>a.kind);return n`
      <div class="header">
        <div>
          <h1>// POLICY</h1>
          <div class="subtitle dc-hint">
            Operator overlay tree at ${t?.dir??"—"}.
            Read-only for now — edit + test land in the next stage.
          </div>
        </div>
        <div class="meta">
          ${r.length} bundles
          ${this.listPoll.state.freshness==="stale"?n` · <span style="color: var(--dc-medium);">stale</span>`:d}
        </div>
      </div>

      ${e?n`<div class="err">✗ ${e.message}</div>`:d}
      ${t?.note?n`<div class="err" style="border-color: var(--dc-medium); color: var(--dc-medium);">⚠ ${t.note}</div>`:d}

      <div class="body">
        <div class="tree">${this.renderTree(s)}</div>
        <div class="viewer">${this.renderViewer()}</div>
      </div>
    `}renderTree(t){return t.size===0?n`<div class="empty">no bundles</div>`:$r.filter(r=>t.has(r)).map(r=>{const s=t.get(r)??[];return n`
        <div class="group">${yr[r]??r.toUpperCase()}</div>
        ${s.map(a=>n`
          <div
            class="item ${this.selectedPath===a.rel_path?"active":""}"
            @click=${()=>this.select(a.rel_path)}
            title=${a.rel_path}
          >
            <span class="path">${a.rel_path}</span>
            <span class="size">${qt(a.size)}</span>
          </div>
        `)}
      `})}renderViewer(){if(this.contentLoading)return n`<div class="empty">loading…</div>`;if(this.contentErr)return n`<div class="empty err">✗ ${this.contentErr}</div>`;if(!this.content)return n`<div class="empty">click a bundle on the left to view</div>`;const t=this.content;return n`
      <div class="viewer-header">
        <span class="kind-badge">${t.kind}</span>
        <span class="name" title=${t.abs_path}>${t.rel_path}</span>
        <span class="right">
          <span class="meta">${qt(t.size)} · ${new Date(t.modified).toLocaleString()}</span>
          <button title="not yet wired — edit endpoint lands in REM-9 stage 2" disabled>EDIT</button>
          <button title="not yet wired — test endpoint lands in REM-9 stage 2" disabled>TEST</button>
        </span>
      </div>
      <pre>${t.content}</pre>
    `}};P.styles=g`
    :host { display: grid; grid-template-rows: auto minmax(0, 1fr); gap: var(--dc-space-3); height: 100%; min-height: 0; }

    .header {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: var(--dc-space-3);
    }
    h1 {
      margin: 0;
      font-size: var(--dc-fs-lg);
      letter-spacing: 0.18em;
      color: var(--dc-text-bright);
      text-transform: uppercase;
    }
    .subtitle { color: var(--dc-text-faint); font-size: var(--dc-fs-sm); }
    .meta { color: var(--dc-text-muted); font-size: var(--dc-fs-xs); letter-spacing: 0.06em; }

    .body {
      display: grid;
      grid-template-columns: 320px minmax(0, 1fr);
      gap: var(--dc-space-3);
      min-height: 0;
    }

    .tree {
      overflow: auto;
      background: var(--dc-surface-1);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-md);
    }
    .group {
      padding: 8px 12px 4px;
      color: var(--dc-text-faint);
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.14em;
      border-top: 1px solid var(--dc-border);
    }
    .group:first-child { border-top: none; }
    .item {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 6px;
      align-items: center;
      padding: 5px 12px 5px 18px;
      cursor: pointer;
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-sm);
      color: var(--dc-text);
    }
    .item:hover { background: var(--dc-row-hover); }
    .item.active {
      background: var(--dc-surface-2);
      color: var(--dc-text-bright);
      border-left: 2px solid var(--dc-accent);
      padding-left: 16px;
    }
    .path { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .size { color: var(--dc-text-faint); font-size: var(--dc-fs-xs); }

    .viewer {
      display: grid;
      grid-template-rows: auto minmax(0, 1fr);
      background: var(--dc-surface-1);
      border: 1px solid var(--dc-border);
      border-radius: var(--dc-radius-md);
      overflow: hidden;
    }
    .viewer-header {
      display: flex;
      gap: var(--dc-space-3);
      align-items: center;
      padding: 10px 14px;
      background: var(--dc-surface-2);
      border-bottom: 1px solid var(--dc-border);
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-sm);
    }
    .viewer-header .name { color: var(--dc-text-bright); font-weight: 700; flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .viewer-header .right { display: flex; align-items: center; gap: var(--dc-space-2); }
    .kind-badge {
      display: inline-block;
      padding: 1px 8px;
      border: 1px solid var(--dc-accent);
      color: var(--dc-accent);
      border-radius: var(--dc-radius-sm);
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.10em;
      text-transform: uppercase;
    }
    button:disabled { opacity: 0.4; cursor: not-allowed; }
    button[title]:hover[disabled] { border-color: var(--dc-border); }

    pre {
      margin: 0;
      padding: var(--dc-space-3);
      background: var(--dc-bg);
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-sm);
      color: var(--dc-text);
      white-space: pre;
      overflow: auto;
    }
    .empty {
      padding: var(--dc-space-5);
      color: var(--dc-text-muted);
      font-style: italic;
      text-align: center;
    }
    .err {
      padding: var(--dc-space-2) var(--dc-space-3);
      border: 1px solid var(--dc-critical);
      border-radius: var(--dc-radius-sm);
      color: var(--dc-critical);
      font-size: var(--dc-fs-sm);
      margin-bottom: var(--dc-space-2);
    }
  `;et([l()],P.prototype,"selectedPath",2);et([l()],P.prototype,"content",2);et([l()],P.prototype,"contentErr",2);et([l()],P.prototype,"contentLoading",2);P=et([b("dc-policy")],P);function xr(t,e){const r=new Map;for(const s of t){const a=e(s),i=r.get(a)??[];i.push(s),r.set(a,i)}return r}function qt(t){return t<1024?`${t} B`:t<1024*1024?`${(t/1024).toFixed(1)} KB`:`${(t/1024/1024).toFixed(1)} MB`}var wr=Object.defineProperty,_r=Object.getOwnPropertyDescriptor,rt=(t,e,r,s)=>{for(var a=s>1?void 0:s?_r(e,r):e,i=t.length-1,o;i>=0;i--)(o=t[i])&&(a=(s?o(e,r,a):o(a))||a);return s&&a&&wr(e,r,a),a};const kr=[{id:"overview",label:"Overview"},{id:"alerts",label:"Alerts"},{id:"inventory",label:"Inventory"},{id:"policy",label:"Policy"},{id:"audit",label:"Audit"},{id:"logs",label:"Logs"},{id:"setup",label:"Setup"}];let D=class extends m{constructor(){super(...arguments),this.open=!1,this.query="",this.wizards=[],this.activeIdx=0,this.close=()=>{this.dispatchEvent(new CustomEvent("dc:palette-close",{bubbles:!0,composed:!0}))},this.onKey=t=>{const e=this.filtered;if(t.key==="Escape"){t.preventDefault(),this.close();return}if(t.key==="ArrowDown"){t.preventDefault(),this.activeIdx=Math.min(this.activeIdx+1,Math.max(e.length-1,0));return}if(t.key==="ArrowUp"){t.preventDefault(),this.activeIdx=Math.max(this.activeIdx-1,0);return}if(t.key==="Enter"){t.preventDefault();const r=e[this.activeIdx];r&&(r.invoke()||this.close())}},this.onInput=t=>{this.query=t.target.value,this.activeIdx=0}}connectedCallback(){super.connectedCallback(),this.loadWizards()}willUpdate(t){t.has("open")&&this.open&&(this.query="",this.activeIdx=0,queueMicrotask(()=>{this.renderRoot?.querySelector("input")?.focus()}))}async loadWizards(){try{const t=await v.get("/v1/setup/wizards");this.wizards=t.wizards}catch{}}navigate(t){window.location.hash=`#/${t}`,this.close()}goSetupWizard(t){window.location.hash=`#/setup?wizard=${encodeURIComponent(t)}`,this.close()}get entries(){const t=[];for(const r of kr)t.push({id:`nav:${r.id}`,label:`Go to ${r.label}`,category:"navigate",hint:`#/${r.id}`,invoke:()=>this.navigate(r.id)});const e=["wizards","sinks","webhooks","config"];for(const r of e)t.push({id:`nav:setup-${r}`,label:`Go to Setup → ${r.charAt(0).toUpperCase()+r.slice(1)}`,category:"navigate",hint:"#/setup",invoke:()=>this.navigate("setup"),search:`setup ${r} go to`});for(const r of this.wizards)t.push({id:`wizard:${r.name}`,label:`Run wizard: ${r.name}`,category:"setup",hint:`defenseclaw ${r.argv_prefix.join(" ")}`,invoke:()=>this.goSetupWizard(r.name)});return t}get filtered(){const t=this.query.trim().toLowerCase();if(!t)return this.entries;const e=[];for(const r of this.entries){const s=(r.search??`${r.label} ${r.hint??""} ${r.category}`).toLowerCase(),a=Er(s,t);a>0&&e.push({e:r,score:a})}return e.sort((r,s)=>s.score-r.score),e.map(r=>r.e)}render(){if(!this.open)return d;const t=this.filtered,e=Sr(t,r=>r.category);return n`
      <div class="scrim" @click=${r=>{r.target===r.currentTarget&&this.close()}}>
        <div class="modal" role="dialog" aria-label="Command palette">
          <div class="header">
            <span>// COMMAND PALETTE</span>
            <span class="key">esc to close</span>
          </div>
          <input
            type="text"
            placeholder="Type to filter — try ‘alerts’, ‘sinks’, ‘mcp set’…"
            .value=${this.query}
            @input=${this.onInput}
            @keydown=${this.onKey}
            spellcheck="false"
            autocomplete="off"
            autocapitalize="off"
          />
          <div class="results">
            ${t.length===0?n`<div class="empty">no matches</div>`:Array.from(e.entries()).map(([r,s])=>n`
                  <div class="group-header">${r}</div>
                  ${s.map(a=>{const i=t.indexOf(a);return n`
                      <div
                        class="row ${i===this.activeIdx?"active":""}"
                        @click=${()=>{a.invoke()||this.close()}}
                        @mouseenter=${()=>{this.activeIdx=i}}
                      >
                        <div>
                          <div class="label">${a.label}</div>
                          ${a.hint?n`<div class="hint">${a.hint}</div>`:d}
                        </div>
                        <span class="cat">${a.category}</span>
                      </div>
                    `})}
                `)}
          </div>
          <div class="footer">
            <span>↑↓ <code>navigate</code></span>
            <span>↵ <code>select</code></span>
            <span>esc <code>close</code></span>
            <span>${t.length} ${t.length===1?"match":"matches"}</span>
          </div>
        </div>
      </div>
    `}};D.styles=g`
    :host {
      display: contents;
    }

    .scrim {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.55);
      z-index: 10000;
      display: grid;
      align-items: start;
      justify-items: center;
      padding-top: 12vh;
    }

    .modal {
      width: min(640px, 92vw);
      background: var(--dc-surface-1);
      border: 1px solid var(--dc-primary);
      border-radius: var(--dc-radius-md);
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.55);
      overflow: hidden;
      display: grid;
      grid-template-rows: auto auto minmax(0, 1fr) auto;
      max-height: 70vh;
    }

    .header {
      padding: 8px 14px;
      border-bottom: 1px solid var(--dc-border);
      background: var(--dc-surface-2);
      color: var(--dc-text-faint);
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.18em;
      text-transform: uppercase;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .header .key {
      color: var(--dc-text-muted);
      font-size: var(--dc-fs-xs);
    }

    input {
      background: var(--dc-bg);
      color: var(--dc-text-bright);
      border: none;
      border-bottom: 1px solid var(--dc-border);
      padding: 14px 16px;
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-lg);
      letter-spacing: 0.04em;
      width: 100%;
    }
    input:focus { outline: none; }

    .results {
      overflow-y: auto;
      padding: 4px 0;
    }

    .group-header {
      padding: 8px 16px 4px;
      color: var(--dc-text-faint);
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.18em;
      text-transform: uppercase;
    }

    .row {
      display: grid;
      grid-template-columns: 1fr auto;
      align-items: center;
      gap: 12px;
      padding: 8px 16px;
      cursor: pointer;
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-md);
      color: var(--dc-text);
    }
    .row:hover, .row.active {
      background: var(--dc-row-hover);
    }
    .row.active {
      background: var(--dc-surface-2);
      border-left: 2px solid var(--dc-accent);
      padding-left: 14px;
    }
    .label { color: var(--dc-text-bright); }
    .hint  { color: var(--dc-text-muted); font-size: var(--dc-fs-xs); }
    .cat   { color: var(--dc-text-faint); font-size: var(--dc-fs-xs); letter-spacing: 0.10em; text-transform: uppercase; }

    .footer {
      padding: 6px 14px;
      border-top: 1px solid var(--dc-border);
      background: var(--dc-surface-2);
      color: var(--dc-text-faint);
      font-size: var(--dc-fs-xs);
      letter-spacing: 0.10em;
      display: flex;
      gap: var(--dc-space-3);
      flex-wrap: wrap;
    }
    .footer code {
      color: var(--dc-text-muted);
      font-family: var(--dc-font-mono);
      font-size: var(--dc-fs-xs);
    }

    .empty {
      padding: 18px 16px;
      color: var(--dc-text-muted);
      font-style: italic;
      font-size: var(--dc-fs-sm);
    }
  `;rt([H({type:Boolean})],D.prototype,"open",2);rt([l()],D.prototype,"query",2);rt([l()],D.prototype,"wizards",2);rt([l()],D.prototype,"activeIdx",2);D=rt([b("dc-command-palette")],D);function Er(t,e){if(t.includes(e))return t.startsWith(e)?1e3:new RegExp(`\\b${Ar(e)}`).test(t)?800:500;let r=0;for(const s of e){const a=t.indexOf(s,r);if(a===-1)return 0;r=a+1}return 100-(r-e.length)}function Ar(t){return t.replace(/[.*+?^${}()|[\]\\]/g,"\\$&")}function Sr(t,e){const r=new Map;for(const s of t){const a=e(s),i=r.get(a)??[];i.push(s),r.set(a,i)}return r}
