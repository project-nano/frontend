#!/bin/bash
WebRoot=./web_root
SourcePath=../portal
WebSource=$SourcePath/build

if [ ! -d "$WebSource" ]; then
	echo $WebSource not exists
	exit 1
fi

if [ -d "$WebRoot" ]; then
  #clear previous content
  if rm -Rf "$WebRoot/*" ; then
    echo previous web root content cleared
  else
    echo clear previous web root content fail
    exit 1
  fi
elif mkdir "$WebRoot"; then
  echo new path "$WebRoot" created
fi

if cp -R $WebSource/* $WebRoot; then
  echo all web files in $WebSource copied to $WebRoot
  echo fetch success
  exit 0
else
  echo fetch $WebSource fail
  exit 1
fi


