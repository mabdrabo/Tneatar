from django.conf.urls import patterns, include, url
from django.views.generic import TemplateView
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    url(r'^admin/', include(admin.site.urls)),
    url(r'^about$', TemplateView.as_view(template_name='about.html'), name="about"),
)

urlpatterns += patterns('tneatar_app.views',
	url(r'^$', "master", name="home"),
	url(r'^signup$', "signup", name="signup"),
	url(r'^signin$', "signin", name="signin"),
	url(r'^signout$', "signout", name="signout"),
	url(r'^dashboard$', "dashboard", name="dashboard"),
    url(r'^profile/(?P<username>\w+)$', "dashboard", name="profile"),
    url(r'^tneat$', "tneat", name="tneat"),
    url(r'^message/send$', "send_message", name="send_message"),
    url(r'^message/index$', "index_messages", name="index_messages"),
    url(r'^message/show/(?P<username>\w+)$', "read_messages", name="show_message"),
    url(r'^follow/add$', "follow", name="follow"),
    url(r'^follow/delete$', "unfollow", name="unfollow"),
    url(r'^follow/index$', "index_follow", name="index_follow"),
    url(r'^follow/accept$', "accept_follow", name="accept_follow"),
    url(r'^tneatas/testing$', "tneatas_testing", name="tneatas_testing"),
)
