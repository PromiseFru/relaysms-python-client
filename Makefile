python=python3
PROTO_DIR=protos/v1
SUPPORTED_PLATFORMS_URL="https://raw.githubusercontent.com/smswithoutborders/SMSWithoutBorders-Publisher/feature/grpc-api/resources/platforms.json"

define log_message
	@echo "[$(shell date +'%Y-%m-%d %H:%M:%S')] - $1"
endef

grpc-compile:
	$(call log_message,INFO - Compiling gRPC protos ...)
	@$(python) -m grpc_tools.protoc \
		-I$(PROTO_DIR) \
		--python_out=. \
		--pyi_out=. \
		--grpc_python_out=. \
		$(PROTO_DIR)/*.proto
	$(call log_message,INFO - gRPC Compilation complete!)

define download-proto
	$(call log_message,INFO - Downloading $(PROTO_URL) to $@ ...)
	@mkdir -p $(dir $@) && \
	curl -o $@ -L $(PROTO_URL)
	$(call log_message,INFO - $@ downloaded successfully!)
endef

$(PROTO_DIR)/%.proto:
	$(eval PROTO_URL := $(PROTO_URL))
	$(call download-proto)

vault-proto: 
	@rm -f "$(PROTO_DIR)/vault.proto"
	@$(MAKE) PROTO_URL=https://raw.githubusercontent.com/smswithoutborders/SMSwithoutborders-BE/feature/grpc_api/protos/v1/vault.proto \
	$(PROTO_DIR)/vault.proto

publisher-proto: 
	@rm -f "$(PROTO_DIR)/publisher.proto"
	@$(MAKE) PROTO_URL=https://raw.githubusercontent.com/smswithoutborders/SMSwithoutborders-Publisher/feature/grpc-api/protos/v1/publisher.proto \
	$(PROTO_DIR)/publisher.proto

download-platforms:
	$(call log_message,INFO - Starting download of platforms JSON file ...)
	@curl -o platforms.json -L "${SUPPORTED_PLATFORMS_URL}"
	$(call log_message,INFO - Platforms JSON file downloaded successfully.)

setup: download-platforms vault-proto publisher-proto grpc-compile
	$(call log_message,INFO - Setup completed.)
