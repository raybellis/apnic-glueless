
#include "base.h"
#include "process.h"
#include "utils.h"

class ParentHandler : public Base {
public:
	ParentHandler(const int *fds);
	virtual void callback(evldns_server_request *srq, ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_class qclass);
};

ParentHandler::ParentHandler(const int* fds) :
	Base(fds)
{
}

void ParentHandler::callback(evldns_server_request *srq, ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_class qclass)
{
}

static void *instance(void *userdata)
{
	Base *handler = static_cast<Base *>(userdata);
	handler->start();

	return NULL;
}

int main(int argc, char *argv[])
{
	int *fds = bind_to_all(NULL, "5053", 100);
	ParentHandler handler(fds);

	farm(1, 0, instance, &handler, 0);

	return 0;
}
