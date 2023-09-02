from building import *

cwd     = GetCurrentDir()
src     = Glob('cJSON.c')
src     += Glob('cJSON_Utils.c')

CPPPATH = [cwd]

group = DefineGroup('cJSON', src, depend = ['PKG_USING_CJSON'], CPPPATH = CPPPATH)

Return('group')
