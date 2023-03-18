/* Tests simply prints "hello, world!", which should return immediately. */

#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "devices/timer.h"

void
test_hello_world (void) 
{
  printf("hello, world!");
  pass ();
}

