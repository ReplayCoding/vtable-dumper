project('vtable_dumper', 'cpp',
  version : '0.1',
  default_options : ['warning_level=3', 'cpp_std=c++20'])

lief_dep = dependency('LIEF')
fmt_dep = dependency('fmt')
executable('vtable_dumper',
           'main.cpp',
           'vtable.cpp',
           dependencies: [lief_dep, fmt_dep],
           install : true)
