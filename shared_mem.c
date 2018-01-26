/*
 * lookup.c
 *
 *  Created on: 2018-01-13
 *      Author: malego
 */

#include <shared_mem.h>


/*

int open_segment( key_t keyval, int segsize )
{
        int     shmid;

        if((shmid = shmget( keyval, segsize, IPC_CREAT | 0660 )) == -1)
        {
                return(-1);
        }

        return(shmid);
}

char *attach_segment( int shmid )
{
        return(shmat(shmid, 0, 0));
}

int shmdt ( char *shmaddr );
*/
