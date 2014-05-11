from django.conf.urls import patterns, include, url
from django.views.generic import TemplateView
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    url(r'^admin/', include(admin.site.urls)),
    url(r'^about$', TemplateView.as_view(template_name='about.html'), name="about"),
	url(r'^contact$', TemplateView.as_view(template_name='contact.html'), name="contact"),
)

urlpatterns += patterns('tneatar_app.views',
	url(r'^$', "master", name="home"),
	url(r'^signup$', "signup", name="signup"),
	url(r'^signin$', "signin", name="signin"),
	url(r'^signout$', "signout", name="signout"),
	url(r'^dashboard$', "dashboard", name="dashboard"),
    url(r'^tneat$', "tneat", name="tneat"),
    url(r'^message$', "send_direct_message", name="send_direct_message"),
    url(r'^follow$', "follow", name="follow"),
    url(r'^unfollow$', "unfollow", name="unfollow"),
	url(r'^email/send$', "email_send", name="email_send"),
)
