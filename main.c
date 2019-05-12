#include <stdio.h>	//For standard things
#include <stdlib.h>	//malloc
#include <string.h>	//memset
#include <netinet/ip_icmp.h>	//Provides declarations for icmp header
#include <netinet/udp.h>	//Provides declarations for udp header
#include <netinet/tcp.h>	//Provides declarations for tcp header
#include <netinet/ip.h>	//Provides declarations for ip header
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>       
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h> 
#include <sys/shm.h>
#include <dirent.h> 

#define SHMSZ     27

// to store all ip and count for iface and have a quick access to it, I use avl tree
// the key of balance is our ip
// start of tree realization
struct node 
{ 
    int ip;
	int count;
    struct node *left; 
    struct node *right; 
    int height; 
} *tree_root = NULL; 
  
// A utility function to get the height of the tree 
int height(struct node *n) 
{ 
    if (n == NULL) 
        return 0; 
    return n->height; 
} 
  
// A utility function to get maximum of two integers 
int max(int a, int b) 
{ 
    return (a > b)? a : b; 
} 
  
/* Helper function that allocates a new node with the given key and 
    NULL left and right pointers. */
struct node* newnode(int ip, int count) 
{ 
    struct node* node = (struct node*) 
                        malloc(sizeof(struct node)); 
    node->ip     = ip; 
	node->count  = count;
    node->left   = NULL; 
    node->right  = NULL; 
    node->height = 1;  // new node is initially added at leaf 
    return(node); 
} 
  
// A utility function to right rotate subtree rooted with y 
// See the diagram given above. 
struct node *rightRotate(struct node *y) 
{ 
    struct node *x = y->left; 
    struct node *t2 = x->right; 
  
    // Perform rotation 
    x->right = y; 
    y->left = t2; 
  
    // Update heights 
    y->height = max(height(y->left), height(y->right))+1; 
    x->height = max(height(x->left), height(x->right))+1; 
  
    // Return new root 
    return x; 
} 
  
// A utility function to left rotate subtree rooted with x 
// See the diagram given above. 
struct node *leftRotate(struct node *x) 
{ 
    struct node *y = x->right; 
    struct node *t2 = y->left; 
  
    // Perform rotation 
    y->left = x; 
    x->right = t2; 
  
    //  Update heights 
    x->height = max(height(x->left), height(x->right))+1; 
    y->height = max(height(y->left), height(y->right))+1; 
  
    // Return new root 
    return y; 
} 
  
// Get Balance factor of node N 
int getBalance(struct node *n) 
{ 
    if (n == NULL) 
        return 0; 
    return height(n->left) - height(n->right); 
} 
  
// Recursive function to insert a key in the subtree rooted 
// with node and returns the new root of the subtree. 
struct node* insert(struct node* node, int ip, int count) 
{ 
    /* 1.  Perform the normal BST insertion */
    if (node == NULL) 
        return(newnode(ip, count)); 
  
    if (ip < node->ip) 
        node->left  = insert(node->left, ip, count); 
    else if (ip > node->ip) 
        node->right = insert(node->right, ip, count); 
    else // Equal keys are not allowed in BST 
        return node; 
  
    /* 2. Update height of this ancestor node */
    node->height = 1 + max(height(node->left), height(node->right)); 
  
    /* 3. Get the balance factor of this ancestor 
          node to check whether this node became 
          unbalanced */
    int balance = getBalance(node); 
  
    // If this node becomes unbalanced, then 
    // there are 4 cases 
  
    // Left Left Case 
    if (balance > 1 && ip < node->left->ip) 
        return rightRotate(node); 
  
    // Right Right Case 
    if (balance < -1 && ip > node->right->ip) 
        return leftRotate(node); 
  
    // Left Right Case 
    if (balance > 1 && ip > node->left->ip) 
    { 
        node->left = leftRotate(node->left); 
        return rightRotate(node); 
    } 
  
    // Right Left Case 
    if (balance < -1 && ip < node->right->ip) 
    { 
        node->right = rightRotate(node->right); 
        return leftRotate(node); 
    } 
  
    /* return the (unchanged) node pointer */
    return node; 
} 
  
// A utility function to print preorder traversal 
// of the tree. 
// The function also prints height of every node 
void preOrder(struct node *root) 
{ 
    if(root != NULL) 
    { 
        preOrder(root->left); 
        printf("%d %d\n", root->ip, root->count); 
        preOrder(root->right); 
    } 
} 

//function that increase ip's counter
void increase(struct node *root, int ip)
{
	if(root == NULL) //only if we inc node in empty tree
	{
		tree_root = newnode(ip, 1);
		return;
	}
	if(root->ip == ip)
	{
		root->count++;
		return;
	}
	struct node* res = root;
	if(ip < root->ip)
	{
		if(root->left == NULL)
		{
			tree_root = insert(tree_root, ip, 1);
			return;
		}
		increase(root->left, ip);
	} else
	{
		if(root->right == NULL)
		{
			tree_root = insert(tree_root, ip, 1);
			return;
		}
		increase(root->right, ip);
	}
}

//making tree empty
struct node* clear(struct node* root)
{
	if(root == NULL) return NULL;
	clear(root->left);
	clear(root->right);
	free(root);
	return NULL;
}
//end of tree realization

int sock_raw;
int total = 0;
struct sockaddr_in source, dest;
char iface[];
FILE* output;

int start();
int stop();
void show(int ip);
int select_iface(char* iface);
int stat(char*);
int help();
void clean();

int main(int argc, char* argv[])
{
	if(argc < 2)
	{
		printf("Error: you should write parametr\n");
		return 1;
	}
	if(argc == 2 && !strcmp(argv[1], "start")) start();
	if(argc == 2 && !strcmp(argv[1], "stop")) stop();
	if(argc == 4 && !strcmp(argv[1], "show") && !strcmp(argv[3], "count")) show(inet_addr(argv[2]));
	if(argc == 4 && !strcmp(argv[1], "select") && !strcmp(argv[2], "iface")) select_iface(argv[3]);
	if(argc == 2 && !strcmp(argv[1], "--help")) help();
	if(argc == 2 && !strcmp(argv[1], "stat")) stat("");
	if(argc == 3 && !strcmp(argv[1], "stat")) stat(argv[2]);
	return 0;
}

void print_tree(struct node* root)
{
	if(root == NULL)
		return;
	print_tree(root->left);
	struct in_addr ip_addr;
    ip_addr.s_addr = root->ip;
	fprintf(output, "%s %d\n", inet_ntoa(ip_addr), root->count);
	print_tree(root->right);
}

int print_count_for_ip(int ip)
{
	struct node* now = tree_root;
	while(now != NULL)
	{
		if(now->ip == ip) return now->count;
		if(ip < now->ip)
			now = now->left;
		else
			now = now->right;
	}
	return 0;
}

int start()
{
	int saddr_size , data_size;
	struct sockaddr saddr;
	struct in_addr in;
	int count = 0;
	unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!

	FILE* system_input = fopen("system.txt", "r");
	int child_proc;
	fscanf(system_input, "%s%d", &iface, &child_proc);
	fclose(system_input);
	if(child_proc != -1)
	{
		printf("Error: proces is already running");
		return 1;
	}

	printf("Starting...\n");
	//Create a raw socket that shall sniff
	sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
	if(sock_raw < 0)
	{
		printf("Socket Error\n");
		return 1;
	}

    struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), iface);
	if (setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
		printf("Problem with conection to interface\n");
		return 1;
	}
	int pid = fork();
	if(pid)
		return 0;
	pid = fork();
	if(!pid)
		while(1);
	system_input = fopen("system.txt", "w");
	fprintf(system_input, "%s\n%d\n%d", iface, pid, sock_raw);
	fclose(system_input);
	int status;
	
	//create shared memory with proccess that call show function
	key_t shared_memory_key = 5987;
	int shmid;
	if ((shmid = shmget(shared_memory_key, SHMSZ, IPC_CREAT | 0666)) < 0) 
	{
        perror("shmget");
        exit(1);
    }
	int *need, *ip;//if need == 1 than we need to calculate answer for ip and store it in ip
	if ((need = shmat(shmid, NULL, 0)) == (int *) -1) 
	{
        perror("shmat");
        exit(1);
    }
	*need = 0;
	ip = need;
	ip++;

	while(!waitpid(-1, &status, WNOHANG))
	{
		if(*need)
		{
			*ip = print_count_for_ip(*ip);
			*need = 0;
		}
		saddr_size = sizeof saddr;
		//Receive a packet
		data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
		if(data_size < 0)
		{
			//printf("Recvfrom error , failed to get packets\n");
			return 1;
		}
		//Now process the packet
		//ProcessPacket(buffer , data_size);
		struct iphdr *iph = (struct iphdr *)buffer;
		memset(&source, 0, sizeof(source));
		source.sin_addr.s_addr = iph->saddr;
		increase(tree_root, source.sin_addr.s_addr);
		printf("There is %d packets  and last is from %s(%d) \n\r", ++count, inet_ntoa(source.sin_addr), source.sin_addr.s_addr);
	}
	close(sock_raw);
	output = fopen(iface, "w");
	print_tree(tree_root);
	fclose(output);
	//printf("Finished\n");
	return 0;
}

void show(int ip)
{
	printf("---------------------------------------------------------------------\n");
	int shmid;
	key_t shared_memory_key = 5987;
	int *need, *ip_answer;//if need == 1 than another proccess calculate answer for ip and store it in ip_answer
	if ((shmid = shmget(shared_memory_key, SHMSZ, 0666)) < 0) 
	{
        perror("shmget");
        exit(1);
    }
	if ((need = shmat(shmid, NULL, 0)) == (int *) -1) {
        perror("shmat");
        exit(1);
    }
	*need = 1;
	ip_answer = need;
	ip_answer++;
	*ip_answer = ip;
	while(*need)
		sleep(5);
	printf("There is %d packets for this IP\n", *ip_answer);
}

int stop()
{
	FILE* system_input = fopen("system.txt", "r+");
	int ppid;
	int sock_raw;
	fscanf(system_input, "%s%d%d", &iface, &ppid, &sock_raw);
	fseek(system_input, 0, SEEK_SET);
	fprintf(system_input, "%s\n-1\n1\n", iface);  
	fclose(system_input);
	if(ppid == -1)
		return 1;
	shutdown(sock_raw, 2);
	kill(ppid, SIGTERM);
	return 0;
}

int select_iface(char* iface)
{
	int not_stoped = stop();
	FILE* system_input;
	system_input = fopen("system.txt", "w");
	fprintf(system_input, "%s\n", iface);
	fclose(system_input);
	if(!not_stoped)
		start();
}

int help()
{
	printf("Base syntacs: \n\tsudo ./a.out [command].\nAvailable comands:\n");
	printf("\t--help            show usage information\n");
	printf("\tstart             Program starts to stiff packets from particular interface(default: eth0)\n");
	printf("\tstop              Program doesn't sniff packets\n");
	printf("\tshow [ip] count   print number pf packets recived from ip address\n");
	printf("\tselect iface [i]  select interface for sniffing eht0, wlan, ethN, ...\n");
	printf("\tstat [iface]      show all collected statistic for particular interface, if iface is not ommited - for all interfaces\n");
	printf("\tclean             delete all collected statistic, and restore default variable\n");
}

int stat(char* iface)
{
	if(!strcmp(iface, ""))
	{
		struct dirent *de;
		DIR *dr = opendir(".");
		while(de = readdir(dr) != NULL)
			if(strcmp(de->d_name, "Makefile") && strcmp(de->d_name, "main.c") && strcmp(de->d_name, "a.out") && strcmp(de->d_name, "system.txt") && strcmp(de->d_name, "README.md"))
				stat(de->d_name);
		return 0;
	}
	FILE* input = fopen(iface, "r");
	char c = fgetc(input); 
    while (c != EOF) 
    { 
        printf ("%c", c); 
        c = fgetc(input); 
    } 
    fclose(input); 
	return 0;
}

void clean()
{
	stop();
	struct dirent *de;
	DIR *dr = opendir(".");
	while(de = readdir(dr) != NULL)
		if(strcmp(de->d_name, "Makefile") && strcmp(de->d_name, "main.c") && strcmp(de->d_name, "a.out") && strcmp(de->d_name, "system.txt") && strcmp(de->d_name, "README.md"))
			remove(de->d_name);
	closedir(dr);
	FILE* system_input = fopen("system.txt", "w");
	fscanf(system_input, "eth0\n-1\n1");
	fclose(system_input);
}