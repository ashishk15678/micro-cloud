client_sources = [
  'gui.c'
]

cc = meson.get_compiler('c')
raylib_dep = dependency('raylib', required : false)
if not raylib_dep.found()
  raylib_dep = cc.find_library('raylib', required : true)
endif

m_dep = cc.find_library('m', required : true)
threads_dep = dependency('threads')
gl_dep = cc.find_library('GL', required : true)
x11_dep = cc.find_library('X11', required : true)
dl_dep = cc.find_library('dl', required : true)
rt_dep = cc.find_library('rt', required : true)

xrandr_dep = cc.find_library('Xrandr', required : false)
xi_dep = cc.find_library('Xi', required : false)
xxf86vm_dep = cc.find_library('Xxf86vm', required : false)
xcursor_dep = cc.find_library('Xcursor', required : false)
xinerama_dep = cc.find_library('Xinerama', required : false)

extra_x11_deps = []
if xrandr_dep.found()
  extra_x11_deps += xrandr_dep
endif
if xi_dep.found()
  extra_x11_deps += xi_dep
endif
if xxf86vm_dep.found()
  extra_x11_deps += xxf86vm_dep
endif
if xcursor_dep.found()
  extra_x11_deps += xcursor_dep
endif
if xinerama_dep.found()
  extra_x11_deps += xinerama_dep
endif

executable('client',
  client_sources,
  include_directories : inc_dir,
  dependencies : [raylib_dep, m_dep, threads_dep, gl_dep, x11_dep, dl_dep, rt_dep] + extra_x11_deps,
  install : true
)
