APP := dns_packet_parser

CC      := gcc
SRC_FMT := c
CFLAGS  := -g -O0
CFLAGS  += -DDBG 

LDFLAGS := -lpcap

SRC_DIRS := src
SRC_DIRS += 


SRCS := $(foreach dir,$(SRC_DIRS),$(wildcard $(dir)/*.$(SRC_FMT)))
OBJS := $(patsubst %.$(SRC_FMT),bin/%.o,$(SRCS))
DEPS := $(patsubst %.$(SRC_FMT),bin/%.d,$(SRCS))

all: bin/$(APP)

bin/$(APP): $(OBJS)
	@$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

bin/%.o: %.$(SRC_FMT)
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -MMD -MP -MF $(patsubst %.o,%.d,$@) -MT $@ -c $< -o $@

-include $(DEPS)

clean:
	@rm -rf bin $(APP)