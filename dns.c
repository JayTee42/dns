// Inspired by https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <unistd.h>

#define MAX_HOST_NAME_LENGTH 253
#define MAX_LABEL_LENGTH 63
#define DNS_PORT 53
#define UDP_MAX_SIZE 65535
#define ID_FIELD 42
#define SPACE "   "

// Macro to print error messages and die if a condition is not fulfilled:
#define verify(cond, msg) 				\
({ 										\
	if (!(cond)) 						\
	{ 									\
		printf("Error: %s\n", (msg)); 	\
		exit(EXIT_FAILURE); 			\
	} 									\
})

// Macro to prevent buffer overflows:
#define verify_bytes_avail(buf_start, buf_curr, buf_length, count)                                           \
({                                                                                                           \
	size_t _count_read = (size_t)((buf_curr) - (buf_start));                                                 \
	size_t _count_rem = (buf_length) - _count_read;                                                          \
	size_t _count = (count);                                                                                 \
                                                                                                             \
	if (_count_rem < _count)                                                                                 \
	{                                                                                                        \
		printf("Buffer overflow has occurred (%zu bytes needed, %zu bytes remaining).", _count, _count_rem); \
		exit(EXIT_FAILURE);                                                                                  \
	}                                                                                                        \
})

static const char* get_type_string(uint16_t tp)
{
	switch (tp)
	{
	case 1: return "IPv4 address";
	default: return "Unknown";
	}
}

static const char* get_class_string(uint16_t cl)
{
	switch (cl)
	{
	case 1: return "Internet";
	default: return "Unknown";
	}
}

static void prepare_nameserver_sockaddr(struct sockaddr_in* nameserver_sockaddr, const char* nameserver_ip)
{
	// Null all fields:
	memset(nameserver_sockaddr, 0, sizeof(struct sockaddr_in));

	nameserver_sockaddr->sin_family = AF_INET;
	nameserver_sockaddr->sin_port = htons(DNS_PORT);

	// Parse the IP address:
	verify(inet_pton(AF_INET, nameserver_ip, &nameserver_sockaddr->sin_addr) == 1, "Failed to parse nameserver IP address.");
}

static int create_udp_socket()
{
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	verify(sock != -1, "Failed to create UDP socket.");

	return sock;
}

static uint8_t* append_label(size_t i, size_t start, const char* host_query, uint8_t* buf)
{
	// Get the length of the current label:
	size_t label_length = i - start;
	verify(label_length <= MAX_LABEL_LENGTH, "At least one host query label is too long.");

	// Append it:
	*buf = (uint8_t)label_length;
	buf++;

	// Append the label itself:
	memcpy(buf, &host_query[start], label_length);
	buf += label_length;

	return buf;
}

static size_t prepare_request(const char* host_query, uint8_t* buf)
{
	uint8_t* buf_start = buf;

	// Identifier:
	*((uint16_t*)buf) = ID_FIELD;
	buf += 2;

	// Control:
	*((uint16_t*)buf) = (1 << 0); // RD
	buf += 2;

	// Question count:
	*((uint16_t*)buf) = htons(1);
	buf += 2;

	// Answer count:
	*((uint16_t*)buf) = htons(0);
	buf += 2;

	// Authority count:
	*((uint16_t*)buf) = htons(0);
	buf += 2;

	// Additional count:
	*((uint16_t*)buf) = htons(0);
	buf += 2;

	// Append the question:
	size_t host_query_length = strlen(host_query);
	size_t start = 0;

	for (size_t i = 0; i < host_query_length; i++)
	{
		if (host_query[i] == '.')
		{
			buf = append_label(i, start, host_query, buf);		

			// Restart behind the label:
			start = i + 1;
		}
	}

	// Append the last label:
	buf = append_label(host_query_length, start, host_query, buf);

	// Append an additional 0:
	*buf = 0;
	buf++;

	// Append query type:
	*((uint16_t*)buf) = htons(1);
	buf += 2;

	// Append query family:
	*((uint16_t*)buf) = htons(1);
	buf += 2;

	// Return number of bytes:
	return (size_t)(buf - buf_start);
}

// `buf` must have space for (MAX_HOST_NAME_LENGTH + 1) bytes.
static uint8_t* read_host_name(uint8_t* buf, uint8_t* buf_start, size_t buf_length, char* host_name)
{
	// Make sure we have one byte available to start the host name:
	verify_bytes_avail(buf_start, buf, buf_length, 1);

	// Track how long the host name is:
	size_t host_name_length = 0;

	// Remember the buffer pointer before jumping:
	uint8_t* buf_before_jump = NULL;

	while (1)
	{
		// Read the length byte:
		size_t length = *buf;
		buf++;

		// Check if this is a ptr:
		if ((length & 0xC0) == 0xC0)
		{
			// Remember the old buffer pointer if we haven't jumped already:
			if (!buf_before_jump)
			{
				buf_before_jump = buf + 1;
			}

			// Read the rest of the ptr:
			verify_bytes_avail(buf_start, buf, buf_length, 1);
			size_t ptr = ((length & 0x3F) << 8) | *buf;

			// Apply and verify it:
			buf = buf_start + ptr;
			verify_bytes_avail(buf_start, buf, buf_length, 1);
		}
		else if (length > 0)
		{
			// Make sure there are enough bytes left in the buffer:
			verify_bytes_avail(buf_start, buf, buf_length, length);

			// Verify the length of the label:
			verify(length <= MAX_LABEL_LENGTH, "Label is too long.");

			// Verify the length of the host name.
			// Remember to insert a dot if we are not at the beginning!
			size_t new_host_name_length = host_name_length + length;

			if (host_name_length > 0)
			{
				new_host_name_length += 1;
			}

			verify(new_host_name_length <= MAX_HOST_NAME_LENGTH, "Host name is too long.");

			// Insert the dot if necessary:
			if (host_name_length > 0)
			{
				host_name[host_name_length++] = '.';
			}

			// Append the label:
			for (; host_name_length < new_host_name_length; host_name_length++)
			{
				host_name[host_name_length] = (char)*buf;
				buf++;
			}
		}
		else
		{
			// Append the terminating zero:
			host_name[host_name_length] = '\0';

			// Return the old buffer pointer if we have jumped:
			return buf_before_jump ? buf_before_jump : buf;
		}
	}
}

static uint8_t* print_question(uint8_t* buf, uint8_t* buf_start, size_t buf_length)
{
	// Print header:
	printf("%s{\n", SPACE);

	// Print the host name:
	char host_name[MAX_HOST_NAME_LENGTH + 1];
	buf = read_host_name(buf, buf_start, buf_length, host_name);
	printf("%s%shost_name: %s,\n", SPACE, SPACE, host_name);

	// Verify the static part of the question:
	verify_bytes_avail(buf_start, buf, buf_length, 4);

	// Print the type:
	uint16_t tp = ntohs(*(uint16_t*)buf);
	buf += 2;
	printf("%s%stype: %s,\n", SPACE, SPACE, get_type_string(tp));

	// Print the class:
	uint16_t cl = ntohs(*(uint16_t*)buf);
	buf += 2;
	printf("%s%sclass: %s\n", SPACE, SPACE, get_class_string(cl));

	// Print footer:
	printf("%s}", SPACE);

	return buf;
}

static uint8_t* print_answer(uint8_t* buf, uint8_t* buf_start, size_t buf_length)
{
	// Print header:
	printf("%s{\n", SPACE);

	// Print the host name:
	char host_name[MAX_HOST_NAME_LENGTH + 1];
	buf = read_host_name(buf, buf_start, buf_length, host_name);
	printf("%s%shost_name: %s,\n", SPACE, SPACE, host_name);

	// Verify the static part of the answer:
	verify_bytes_avail(buf_start, buf, buf_length, 10);

	// Print the type:
	uint16_t tp = ntohs(*(uint16_t*)buf);
	buf += 2;
	printf("%s%stype: %s,\n", SPACE, SPACE, get_type_string(tp));

	// Print the class:
	uint16_t cl = ntohs(*(uint16_t*)buf);
	buf += 2;
	printf("%s%sclass: %s,\n", SPACE, SPACE, get_class_string(cl));

	// Print the time to live:
	uint32_t ttl = ntohl(*(uint32_t*)buf);
	buf += 4;
	printf("%s%sttl: %" PRIu32 ",\n", SPACE, SPACE, ttl);

	// Read the data length:
	uint16_t data_length = ntohs(*(uint16_t*)buf);
	buf += 2;

	// Verify it:
	verify_bytes_avail(buf_start, buf, buf_length, (size_t)data_length);

	// Print it:
	printf("%s%sdata: ", SPACE, SPACE);

	if (cl == 1)
	{
		switch (tp)
		{
		// IPv4:
		case 1:

			verify(data_length == 4, "Bad IPv4 length");
			printf("%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "\n", buf[0], buf[1], buf[2], buf[3]);

			break;

		default: printf("Unknown type\n");
		}
	}
	else
	{
		printf("Unknown class\n");
	}

	// Increment the buffer:
	buf += data_length;

	// Print footer:
	printf("%s}", SPACE);

	return buf;
}

static void print_response(uint8_t* buf, size_t buf_length)
{
	uint8_t* buf_start = buf;

	// Make sure we have a complete header:
	verify_bytes_avail(buf_start, buf, buf_length, 12);

	// Verify the ID field:
	uint16_t id_field = *(uint16_t*)buf;
	buf += 2;

	verify(id_field == ID_FIELD, "Wrong identifier in response received.");

	// Get the flags:
	uint16_t flags = *(uint16_t*)buf;
	buf += 2;

	// Make sure we have a response:
	verify(flags & (1 << 7), "Response flag is not set.");

	// Make sure recursion is available:
	verify(flags & (1 << 15), "Recursion is not available.");

	// Get the response code:
	uint8_t resp_code = (flags >> 8) & 0x0F;

	if (resp_code != 0)
	{
		printf("Bad response code: ");

		switch (resp_code)
		{
		case 1: printf("FORMERR"); break;
		case 2: printf("SERVFAIL"); break;
		case 3: printf("NXDOMAIN"); break;
		case 4: printf("NOTIMP"); break;
		case 5: printf("REFUSED"); break;
		case 6: printf("YXDOMAIN"); break;
		case 7: printf("XRRSET"); break;
		case 8: printf("NOTAUTH"); break;
		case 9: printf("NOTZONE"); break;

		default: printf("UNKNOWN");
		}

		printf("\n");
		exit(EXIT_FAILURE);
	}

	// Get the counts:
	uint16_t questions_count = ntohs(*(uint16_t*)buf);
	buf += 2;

	uint16_t answers_count = ntohs(*(uint16_t*)buf);
	buf += 6;

	// Don't care for authorities and additionals for now.

	// Print the questions:
	printf("Questions: [\n");

	for (size_t i = 0; i < (size_t)questions_count; i++)
	{
		buf = print_question(buf, buf_start, buf_length);

		if (i != (size_t)(questions_count - 1))
		{
			printf(",");
		}

		printf("\n");
	}

	printf("],\n");

	// Print the answers:
	printf("Answers: [\n");

	for (size_t i = 0; i < (size_t)answers_count; i++)
	{
		buf = print_answer(buf, buf_start, buf_length);

		if (i != (size_t)(answers_count - 1))
		{
			printf(",");
		}

		printf("\n");
	}

	printf("]\n");
}

int main(int argc, char** argv)
{
	// Get nameserver and host query:
	verify(argc >= 3, "Format <nameserver IPv4> <host query> expected!");

	const char* nameserver_ip = argv[1];
	const char* host_query = argv[2];

	// Verify the host query length:
	verify(strlen(host_query) <= MAX_HOST_NAME_LENGTH, "Host query is too long.");

	// Prepare the address struct for the nameserver:
	struct sockaddr_in nameserver_sockaddr;
	prepare_nameserver_sockaddr(&nameserver_sockaddr, nameserver_ip);

	// Create a UDP socket:
	int sock = create_udp_socket();

	// Allocate a sufficiently-sized buffer.
	// This could go on the stack as well, but let's be sure.
	uint8_t* buf = malloc(UDP_MAX_SIZE);
	verify(buf != NULL, "Failed to allocate memory.");

	// Prepare the request:
	size_t buf_length = prepare_request(host_query, buf);

	// Send the request:
	socklen_t address_length = sizeof(struct sockaddr_in);
	size_t sent_length = (size_t)sendto(sock, buf, buf_length, 0, (struct sockaddr*)&nameserver_sockaddr, address_length);
	verify(sent_length == buf_length, "Failed to send datagram.");

	// Receive the answer:
	buf_length = (size_t)recvfrom(sock, buf, UDP_MAX_SIZE, 0, (struct sockaddr*)&nameserver_sockaddr, &address_length);

	// Close the socket;
	close(sock);

	// Print the response:
	print_response(buf, buf_length);

	// Release the heap memory:
	free(buf);

	return 0;
}
