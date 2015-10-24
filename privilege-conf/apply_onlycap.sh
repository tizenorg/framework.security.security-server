#!/bin/sh

ONLYCAP_LIST=/usr/share/privilege-control/onlycap_list
ONLYCAP_FILE=/sys/fs/smackfs/onlycap
#ONLYCAP_LIST=./onlycap_list

if [ -f $ONLYCAP_LIST ]
then
	for label in $( cat $ONLYCAP_LIST )
	do
		list="$list $label"
	done

	echo $list
	echo $list >> $ONLYCAP_FILE
fi
