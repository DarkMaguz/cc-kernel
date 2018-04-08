#!/bin/sh

#dd if=/dev/zero of=enc.img bs=1024 count=30720
#sudo losetup -e cc /dev/loop0 enc.img
#sudo mkfs -t ext3 -m 1 -v /dev/loop0
#sudo losetup -d /dev/loop0

#dd if=/dev/zero of=enc.img bs=1024 count=30720
#sudo losetup /dev/loop0 enc.img
#sudo cryptsetup -c aes -d key.txt create encfile1 /dev/loop0
#sudo mkfs -t ext3 -m 1 -v /dev/mapper/encfile1
#sudo mount /dev/mapper/encfile1 /mnt
#echo "Hello World!"> /mnt/test.txt
#sudo umount /mnt
#sudo dmsetup remove /dev/mapper/encfile1
#sudo losetup -d /dev/loop0

LOOPDEV=/dev/loop0
IMAGEFILE=enc.img
CIPHER=aes
KEYFILE=key.txt
MAPPERFILE=/dev/mapper/encfile1

case $1 in
	start)
		losetup $LOOPDEV $IMAGEFILE
		cryptsetup -c $CIPHER -d $KEYFILE create encfile1 $LOOPDEV
		mount $MAPPERFILE /mnt
	;;
	stop)
		umount /mnt
		cryptsetup remove $MAPPERFILE
		losetup -d $LOOPDEV
	;;
	create)
		rm $IMAGEFILE
		dd status=noxfer if=/dev/zero of=$IMAGEFILE bs=1024 count=30720
		#losetup $LOOPDEV $IMAGEFILE
		./cc b
		cryptsetup -c $CIPHER -d $KEYFILE create encfile1 $LOOPDEV
		#./cc c
		mkfs -q -t ext3 $MAPPERFILE
		#./cc d
		#dumpe2fs $MAPPERFILE
		mount $MAPPERFILE /mnt
		#echo "Hello World!"> /mnt/test.txt
		umount /mnt
		cryptsetup remove $MAPPERFILE
		losetup -d $LOOPDEV
		#rm /mnt/test.txt
	;;
	*)
		echo "Usage: $0 {start|stop|create}"
		exit 1
	;;
esac

