#!/usr/bin/perl
use strict;
use warnings;
use v5.14;
use Data::Dump qw/ddx/;

my @output = `ps -emo user,pid,ppid,lwp,nlwp,etime,time,ni,pri_foo,sgi_p,psr,stat,wchan=WIDE-WCHAN-COLUMN,cls,f,pcpu,pmem,rss,vsz,sz,args`;
print @output
