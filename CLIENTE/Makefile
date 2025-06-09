CC=gcc
OBJETOS=clienteTLS.o encriptador.o desencriptador.o clave_publica_send_recv.o
APP=clienteTLS
CFLAGS = -lssl -lcrypto -lpthread

# $@:Se sustituye por el nombre del objetivo de la presente regla.
# $*:Se sustituye por la raíz de un nombre de fichero.
# $<:Se sustituye por la primera dependencia de la presente regla.
# $^:Se sustituye por una lista separada por espacios de cada una de las dependencias de la presente regla.

all: $(APP)


$(APP): $(OBJETOS)
	$(CC) -o $@ $^ $(CFLAGS)

%.o: %.c
	$(CC) -g -c $< -o $@
	
clean:
	rm $(OBJETOS) $(APP) $(FIRMWARE)
