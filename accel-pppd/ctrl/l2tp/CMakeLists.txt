INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})

ADD_DEFINITIONS(-DDICTIONARY="${CMAKE_INSTALL_PREFIX}/share/accel-ppp/l2tp/dictionary")

ADD_LIBRARY(l2tp SHARED
	l2tp.c
	l2tp_switch_conf.c
	dict.c
	packet.c
	#	netlink.c
)
# musl's dynamic linker doesn't support lazy PLT binding -- it resolves
# every symbol eagerly at dlopen() time regardless of the RTLD_LAZY flag
# accel-ppp's own loader requests (accel-pppd/triton/loader.c), unlike
# glibc, which happily defers connlimit_check's resolution until l2tp.c's
# own runtime triton_module_loaded("connlimit") guard decides whether to
# call it at all. Confirmed the hard way on an Alpine/musl CI target:
# "Error relocating libl2tp.so: connlimit_check: symbol not found" purely
# from loading the module, never mind calling the guarded function.
# pppoe's own CMakeLists.txt already carries this exact same workaround
# for the identical reason -- mirrored here rather than diverging.
IF (MUSL)
	TARGET_LINK_LIBRARIES(l2tp connlimit ${crypto_lib})
ELSE (MUSL)
	TARGET_LINK_LIBRARIES(l2tp ${crypto_lib})
ENDIF (MUSL)
#TARGET_LINK_LIBRARIES(l2tp nl nl-genl)

INSTALL(TARGETS l2tp LIBRARY DESTINATION lib${LIB_SUFFIX}/accel-ppp)

FILE(GLOB dict "${CMAKE_CURRENT_SOURCE_DIR}/dict/*")
INSTALL(FILES ${dict} DESTINATION share/accel-ppp/l2tp)
