#include <stdio.h>
#include <stdlib.h>
#include "init.h"
#include "proc.h"
#include "clean.h"

int main(){

	s_pkt_gl *pkt_gl = pkt_init();
	
	if (!pkt_gl ){
		printf("[INIT ERROR]\n");
		exit(-1);
	}
	
	pkt_proc(pkt_gl);
	
	clean(pkt_gl);
    
    return 0;
	
}
