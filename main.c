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
}; 
  
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
        printf("%d(%d) ", root->ip, root->count); 
        preOrder(root->left); 
        preOrder(root->right); 
    } 
} 

//function that increase ip's counter
struct node* increase(struct node *root, int ip)
{
	if(root == NULL) //only if we inc node in empty tree
		return newnode(ip, 1);
	if(root->ip == ip)
	{
		root->count++;
		return root;
	}
	if(ip < root->ip)
	{
		if(root->left == NULL)
			root->left = newnode(ip, 0);
		increase(root->left, ip);
	} else
	{
		if(root->right == NULL)
			root->right = newnode(ip, 0);
		increase(root->right, ip);
	}
	return root;
}
//end of tree realization

int sock_raw;
int total = 0;
struct sockaddr_in source, dest;
struct node *tree_root = NULL;
char iface[10];

int start();
int stop();
int show();
int select_iface();
int stat();
int help();

int main(int argc, char* argv[])
{
	printf("-----------------------------------------------------------------------\n");
	tree_root = increase(tree_root, 15);
	tree_root = insert(tree_root, 15, 100);
	tree_root = insert(tree_root, 16, 100);
	preOrder(tree_root);
	/*if(argc < 2)
	{
		printf("Error: you should write parametr\n");
		return 1;
	}
	if(argc == 2 && !strcmp(argv[1], "start")) start();
	if(argc == 2 && !strcmp(argv[1], "stop")) stop();
	if(argc == 4 && !strcmp(argv[1], "show") && !strcmp(argv[3], "count")) show();
	if(argc == 4 && !strcmp(argv[1], "select") && !strcmp(argv[2], "iface")) select_iface(argv[3]);
	if(argc == 3 && !strcmp(argv[1], "stat")) stat();
	if(argc == 2 && !strcmp(argv[1], "--help")) help();
	return 0;*/
}

int start()
{
	int saddr_size , data_size;
	struct sockaddr saddr;
	struct in_addr in;
	int count = 0;
	unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!

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
	FILE* system_input = fopen("system.txt", "r");
	char iface[10];
	fscanf(system_input, "%s", &iface);
	fclose(system_input);
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), iface);
	if (setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
		printf("Problem with conection to interface\n");
		return 1;
	}

	while(1)
	{
		saddr_size = sizeof saddr;
		//Receive a packet
		data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
		if(data_size <0 )
		{
			printf("Recvfrom error , failed to get packets\n");
			return 1;
		}
		//Now process the packet
		//ProcessPacket(buffer , data_size);
		struct iphdr *iph = (struct iphdr *)buffer;
		memset(&source, 0, sizeof(source));
		source.sin_addr.s_addr = iph->saddr;

		printf("There is %d packets  and last is from %s(%d) \n\r", ++count, inet_ntoa(source.sin_addr), source.sin_addr);

	}
	close(sock_raw);
	printf("Finished");
	return 0;
}

int stop()
{
	return 0;
}

int show()
{

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

}
