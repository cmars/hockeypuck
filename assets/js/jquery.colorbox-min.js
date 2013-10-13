(function(K,m,Y){var L={transition:"elastic",speed:300,width:false,initialWidth:"600",innerWidth:false,maxWidth:false,height:false,initialHeight:"450",innerHeight:false,maxHeight:false,scalePhotos:true,scrolling:true,inline:false,html:false,iframe:false,fastIframe:true,photo:false,href:false,title:false,rel:false,opacity:0.9,preloading:true,current:"image {current} of {total}",previous:"previous",next:"next",close:"close",xhrError:"This content failed to load.",imgError:"This image failed to load.",open:false,returnFocus:true,reposition:true,loop:true,slideshow:false,slideshowAuto:true,slideshowSpeed:2500,slideshowStart:"start slideshow",slideshowStop:"stop slideshow",onOpen:false,onLoad:false,onComplete:false,onCleanup:false,onClosed:false,overlayClose:true,escKey:true,arrowKey:true,top:false,bottom:false,left:false,right:false,fixed:false,data:undefined},y="colorbox",U="cbox",s=U+"Element",X=U+"_open",e=U+"_load",W=U+"_complete",v=U+"_cleanup",ae=U+"_closed",i=U+"_purge",w=!K.support.opacity&&!K.support.style,ah=w&&!Y.XMLHttpRequest,ac=U+"_IE6",R,ai,aj,d,I,q,b,Q,c,ab,O,k,h,p,u,Z,t,T,A,C,ag,ak,n,g,a,x,J,o,E,aa,N,B,M,af="div",ad;function H(al,ao,an){var am=m.createElement(al);if(ao){am.id=U+ao}if(an){am.style.cssText=an}return K(am)}function F(am){var al=c.length,an=(J+am)%al;return(an<0)?al+an:an}function P(al,am){return Math.round((/%/.test(al)?((am==="x"?l():S())/100):1)*parseInt(al,10))}function D(al){return ag.photo||/\.(gif|png|jp(e|g|eg)|bmp|ico)((#|\?).*)?$/i.test(al)}function l(){return Y.innerWidth||ab.width()}function S(){return Y.innerHeight||ab.height()}function V(){var al,am=K.data(x,y);if(am==null){ag=K.extend({},L);if(console&&console.log){console.log("Error: cboxElement missing settings object")}}else{ag=K.extend({},am)}for(al in ag){if(K.isFunction(ag[al])&&al.slice(0,2)!=="on"){ag[al]=ag[al].call(x)}}ag.rel=ag.rel||x.rel||"nofollow";ag.href=ag.href||K(x).attr("href");ag.title=ag.title||x.title;if(typeof ag.href==="string"){ag.href=K.trim(ag.href)}}function G(al,am){K.event.trigger(al);if(am){am.call(x)}}function z(){var am,ao=U+"Slideshow_",ap="click."+U,aq,an,al;if(ag.slideshow&&c[1]){aq=function(){Z.text(ag.slideshowStop).unbind(ap).bind(W,function(){if(ag.loop||c[J+1]){am=setTimeout(M.next,ag.slideshowSpeed)}}).bind(e,function(){clearTimeout(am)}).one(ap+" "+v,an);ai.removeClass(ao+"off").addClass(ao+"on");am=setTimeout(M.next,ag.slideshowSpeed)};an=function(){clearTimeout(am);Z.text(ag.slideshowStart).unbind([W,e,v,ap].join(" ")).one(ap,function(){M.next();aq()});ai.removeClass(ao+"on").addClass(ao+"off")};if(ag.slideshowAuto){aq()}else{an()}}else{ai.removeClass(ao+"off "+ao+"on")}}function f(al){if(!N){x=al;V();c=K(x);J=0;if(ag.rel!=="nofollow"){c=K("."+s).filter(function(){var an=K.data(this,y),am;if(an){am=an.rel||this.rel}return(am===ag.rel)});J=c.index(x);if(J===-1){c=c.add(x);J=c.length-1}}if(!E){E=aa=true;ai.show();if(ag.returnFocus){K(x).blur().one(ae,function(){K(this).focus()})}R.css({opacity:+ag.opacity,cursor:ag.overlayClose?"pointer":"auto"}).show();ag.w=P(ag.initialWidth,"x");ag.h=P(ag.initialHeight,"y");M.position();if(ah){ab.bind("resize."+ac+" scroll."+ac,function(){R.css({width:l(),height:S(),top:ab.scrollTop(),left:ab.scrollLeft()})}).trigger("resize."+ac)}G(X,ag.onOpen);C.add(p).hide();A.html(ag.close).show()}M.load(true)}}function r(){if(!ai&&m.body){ad=false;ab=K(Y);ai=H(af).attr({id:y,"class":w?U+(ah?"IE6":"IE"):""}).hide();R=H(af,"Overlay",ah?"position:absolute":"").hide();h=H(af,"LoadingOverlay").add(H(af,"LoadingGraphic"));aj=H(af,"Wrapper");d=H(af,"Content").append(O=H(af,"LoadedContent","width:0; height:0; overflow:hidden"),p=H(af,"Title"),u=H(af,"Current"),t=H(af,"Next"),T=H(af,"Previous"),Z=H(af,"Slideshow").bind(X,z),A=H(af,"Close"));aj.append(H(af).append(H(af,"TopLeft"),I=H(af,"TopCenter"),H(af,"TopRight")),H(af,false,"clear:left").append(q=H(af,"MiddleLeft"),d,b=H(af,"MiddleRight")),H(af,false,"clear:left").append(H(af,"BottomLeft"),Q=H(af,"BottomCenter"),H(af,"BottomRight"))).find("div div").css({"float":"left"});k=H(af,false,"position:absolute; width:9999px; visibility:hidden; display:none");C=t.add(T).add(u).add(Z);K(m.body).append(R,ai.append(aj,k))}}function j(){if(ai){if(!ad){ad=true;ak=I.height()+Q.height()+d.outerHeight(true)-d.height();n=q.width()+b.width()+d.outerWidth(true)-d.width();g=O.outerHeight(true);a=O.outerWidth(true);ai.css({"padding-bottom":ak,"padding-right":n});t.click(function(){M.next()});T.click(function(){M.prev()});A.click(function(){M.close()});R.click(function(){if(ag.overlayClose){M.close()}});K(m).bind("keydown."+U,function(am){var al=am.keyCode;if(E&&ag.escKey&&al===27){am.preventDefault();M.close()}if(E&&ag.arrowKey&&c[1]){if(al===37){am.preventDefault();T.click()}else{if(al===39){am.preventDefault();t.click()}}}});K("."+s,m).live("click",function(al){if(!(al.which>1||al.shiftKey||al.altKey||al.metaKey)){al.preventDefault();f(this)}})}return true}return false}if(K.colorbox){return}K(r);M=K.fn[y]=K[y]=function(al,an){var am=this;al=al||{};r();if(j()){if(!am[0]){if(am.selector){return am}am=K("<a/>");al.open=true}if(an){al.onComplete=an}am.each(function(){K.data(this,y,K.extend({},K.data(this,y)||L,al))}).addClass(s);if((K.isFunction(al.open)&&al.open.call(am))||al.open){f(am[0])}}return am};M.position=function(an,ap){var ar,au=0,am=0,aq=ai.offset(),al,ao;ab.unbind("resize."+U);ai.css({top:-90000,left:-90000});al=ab.scrollTop();ao=ab.scrollLeft();if(ag.fixed&&!ah){aq.top-=al;aq.left-=ao;ai.css({position:"fixed"})}else{au=al;am=ao;ai.css({position:"absolute"})}if(ag.right!==false){am+=Math.max(l()-ag.w-a-n-P(ag.right,"x"),0)}else{if(ag.left!==false){am+=P(ag.left,"x")}else{am+=Math.round(Math.max(l()-ag.w-a-n,0)/2)}}if(ag.bottom!==false){au+=Math.max(S()-ag.h-g-ak-P(ag.bottom,"y"),0)}else{if(ag.top!==false){au+=P(ag.top,"y")}else{au+=Math.round(Math.max(S()-ag.h-g-ak,0)/2)}}ai.css({top:aq.top,left:aq.left});an=(ai.width()===ag.w+a&&ai.height()===ag.h+g)?0:an||0;aj[0].style.width=aj[0].style.height="9999px";function at(av){I[0].style.width=Q[0].style.width=d[0].style.width=av.style.width;d[0].style.height=q[0].style.height=b[0].style.height=av.style.height}ar={width:ag.w+a,height:ag.h+g,top:au,left:am};if(an===0){ai.css(ar)}ai.dequeue().animate(ar,{duration:an,complete:function(){at(this);aa=false;aj[0].style.width=(ag.w+a+n)+"px";aj[0].style.height=(ag.h+g+ak)+"px";if(ag.reposition){setTimeout(function(){ab.bind("resize."+U,M.position)},1)}if(ap){ap()}},step:function(){at(this)}})};M.resize=function(al){if(E){al=al||{};if(al.width){ag.w=P(al.width,"x")-a-n}if(al.innerWidth){ag.w=P(al.innerWidth,"x")}O.css({width:ag.w});if(al.height){ag.h=P(al.height,"y")-g-ak}if(al.innerHeight){ag.h=P(al.innerHeight,"y")}if(!al.innerHeight&&!al.height){O.css({height:"auto"});ag.h=O.height()}O.css({height:ag.h});M.position(ag.transition==="none"?0:ag.speed)}};M.prep=function(am){if(!E){return}var ap,an=ag.transition==="none"?0:ag.speed;O.remove();O=H(af,"LoadedContent").append(am);function al(){ag.w=ag.w||O.width();ag.w=ag.mw&&ag.mw<ag.w?ag.mw:ag.w;return ag.w}function ao(){ag.h=ag.h||O.height();ag.h=ag.mh&&ag.mh<ag.h?ag.mh:ag.h;return ag.h}O.hide().appendTo(k.show()).css({width:al(),overflow:ag.scrolling?"auto":"hidden"}).css({height:ao()}).prependTo(d);k.hide();K(o).css({"float":"none"});if(ah){K("select").not(ai.find("select")).filter(function(){return this.style.visibility!=="hidden"}).css({visibility:"hidden"}).one(v,function(){this.style.visibility="inherit"})}ap=function(){var aB,ay,az=c.length,av,aA="frameBorder",au="allowTransparency",ar,aq,ax,aw;if(!E){return}function at(){if(w){ai[0].style.removeAttribute("filter")}}ar=function(){clearTimeout(B);h.detach().hide();G(W,ag.onComplete)};if(w){if(o){O.fadeIn(100)}}p.html(ag.title).add(O).show();if(az>1){if(typeof ag.current==="string"){u.html(ag.current.replace("{current}",J+1).replace("{total}",az)).show()}t[(ag.loop||J<az-1)?"show":"hide"]().html(ag.next);T[(ag.loop||J)?"show":"hide"]().html(ag.previous);if(ag.slideshow){Z.show()}if(ag.preloading){aB=[F(-1),F(1)];while(ay=c[aB.pop()]){aw=K.data(ay,y);if(aw&&aw.href){aq=aw.href;if(K.isFunction(aq)){aq=aq.call(ay)}}else{aq=ay.href}if(D(aq)){ax=new Image();ax.src=aq}}}}else{C.hide()}if(ag.iframe){av=H("iframe")[0];if(aA in av){av[aA]=0}if(au in av){av[au]="true"}av.name=U+(+new Date());if(ag.fastIframe){ar()}else{K(av).one("load",ar)}av.src=ag.href;if(!ag.scrolling){av.scrolling="no"}K(av).addClass(U+"Iframe").appendTo(O).one(i,function(){av.src="//about:blank"})}else{ar()}if(ag.transition==="fade"){ai.fadeTo(an,1,at)}else{at()}};if(ag.transition==="fade"){ai.fadeTo(an,0,function(){M.position(0,ap)})}else{M.position(an,ap)}};M.load=function(an){var am,ao,al=M.prep;aa=true;o=false;x=c[J];if(!an){V()}G(i);G(e,ag.onLoad);ag.h=ag.height?P(ag.height,"y")-g-ak:ag.innerHeight&&P(ag.innerHeight,"y");ag.w=ag.width?P(ag.width,"x")-a-n:ag.innerWidth&&P(ag.innerWidth,"x");ag.mw=ag.w;ag.mh=ag.h;if(ag.maxWidth){ag.mw=P(ag.maxWidth,"x")-a-n;ag.mw=ag.w&&ag.w<ag.mw?ag.w:ag.mw}if(ag.maxHeight){ag.mh=P(ag.maxHeight,"y")-g-ak;ag.mh=ag.h&&ag.h<ag.mh?ag.h:ag.mh}am=ag.href;B=setTimeout(function(){h.show().appendTo(d)},100);if(ag.inline){H(af).hide().insertBefore(K(am)[0]).one(i,function(){K(this).replaceWith(O.children())});al(K(am))}else{if(ag.iframe){al(" ")}else{if(ag.html){al(ag.html)}else{if(D(am)){K(o=new Image()).addClass(U+"Photo").error(function(){ag.title=false;al(H(af,"Error").html(ag.imgError))}).load(function(){var ap;o.onload=null;if(ag.scalePhotos){ao=function(){o.height-=o.height*ap;o.width-=o.width*ap};if(ag.mw&&o.width>ag.mw){ap=(o.width-ag.mw)/o.width;ao()}if(ag.mh&&o.height>ag.mh){ap=(o.height-ag.mh)/o.height;ao()}}if(ag.h){o.style.marginTop=Math.max(ag.h-o.height,0)/2+"px"}if(c[1]&&(ag.loop||c[J+1])){o.style.cursor="pointer";o.onclick=function(){M.next()}}if(w){o.style.msInterpolationMode="bicubic"}setTimeout(function(){al(o)},1)});setTimeout(function(){o.src=am},1)}else{if(am){k.load(am,ag.data,function(aq,ap,ar){al(ap==="error"?H(af,"Error").html(ag.xhrError):K(this).contents())})}}}}}};M.next=function(){if(!aa&&c[1]&&(ag.loop||c[J+1])){J=F(1);M.load()}};M.prev=function(){if(!aa&&c[1]&&(ag.loop||J)){J=F(-1);M.load()}};M.close=function(){if(E&&!N){N=true;E=false;G(v,ag.onCleanup);ab.unbind("."+U+" ."+ac);R.fadeTo(200,0);ai.stop().fadeTo(300,0,function(){ai.add(R).css({opacity:1,cursor:"auto"}).hide();G(i);O.remove();setTimeout(function(){N=false;G(ae,ag.onClosed)},1)})}};M.remove=function(){K([]).add(ai).add(R).remove();ai=null;K("."+s).removeData(y).removeClass(s).die()};M.element=function(){return K(x)};M.settings=L}(jQuery,document,this));