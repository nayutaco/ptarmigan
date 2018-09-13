all: build

build:
	mkdir -p classes
	javac -classpath validation-api-1.0.0.GA.jar -s src -d classes src/co/nayuta/lightning/PtarmiganNative.java

exec:
	LD_LIBRARY_PATH=`pwd` java -classpath classes:validation-api-1.0.0.GA.jar co.nayuta.lightning.PtarmiganNative

header:
	javah -classpath classes co.nayuta.lightning.PtarmiganNative

clean:
	rm -rf classes
