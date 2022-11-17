# Create SSH Templated Policy
vault policy write team-1-ssh -<<EOF
path "ssh-client-signer-team-1/sign/{{identity.entity.name}}" {
    capabilities = ["create","update"]
}
EOF


# Create a Control Group Policy
vault policy write sign-ssh-key -<<EOF
path "ssh-client-signer-team-1/sign/bob" {
  capabilities = [ "create", "update" ]

  control_group = {
    factor "authorizer" {
        identity {
            group_names = [ "request-approver" ]
            approvals = 1
        }
    }
  }
}
EOF


# Create Policy for Request Approver
vault policy write request-approver -<<EOF
# To approve the request
path "sys/control-group/authorize" {
    capabilities = ["create", "update"]
}

# To check control group request status
path "sys/control-group/request" {
    capabilities = ["create", "update"]
}
EOF


# Enable userpass
vault auth enable userpass

# Create a user, bob
vault write auth/userpass/users/bob password="training"

# Create a user, ellen
vault write auth/userpass/users/ellen password="training"

# Retrieve the userpass mount accessor and save it in a file named accessor.txt
vault auth list -format=json | jq -r '.["userpass/"].accessor' > accessor.txt

# Create bpb entity and save the identity ID in the entity_id_bob.txt
vault write -format=json identity/entity name="bob" policies="sign-ssh-key, team-1-ssh" \
        metadata=team="SSH Requester" \
        | jq -r ".data.id" > entity_id_bob.txt

# Add an entity alias for bob entity
vault write identity/entity-alias name="bob" \
       canonical_id=$(cat entity_id_bob.txt) \
       mount_accessor=$(cat accessor.txt)

# Create ellen entity and save the identity ID in the entity_id_ellen.txt
vault write -format=json identity/entity name="ellen" policies="default" \
        metadata=team="Request Approver" \
        | jq -r ".data.id" > entity_id_ellen.txt

# Add an entity alias for ellen entity
vault write identity/entity-alias name="ellen" \
       canonical_id=$(cat entity_id_ellen.txt) \
       mount_accessor=$(cat accessor.txt)

# Finally, create request-approver group and add ellen entity as a member
vault write identity/group name="request-approver" \
      policies="request-approver" \
      member_entity_ids=$(cat entity_id_ellen.txt)

# Enable ssh-client-signer-team-1 signing engine
vault secrets enable -path=ssh-client-signer-team-1 ssh

# Generate Signing Cert
vault write ssh-client-signer-team-1/config/ca generate_signing_key=true

# Create a role for bob with scoped permissions
vault write ssh-client-signer-team-1/roles/bob -<<"EOH"
{
  "allow_user_certificates": true,
  "allowed_users": "bob",
  "default_extensions": [
    {
      "permit-pty": ""
    }
  ],
  "key_type": "ca",
  "default_user": "",
  "ttl": "30m0s"
}
EOH

# Login as bob
vault login -method=userpass username="bob" password="training"

# Run command to sign bob's key 
# NOTE: Keep track of wrapping_token and wrapping_accessor
vault write -field=signed_key ssh-client-signer-team-1/sign/bob public_key=@$HOME/.ssh/id_rsa.pub > signed-cert.pub

# Login as ellen
vault login -method=userpass username="ellen" password="training"

# Look up bob's request using the wrapping_accessor
vault write sys/control-group/request accessor=<BOBS_WRAPPING_ACCESSOR>

# Approve bob's request using the wrapping_accessor
vault write sys/control-group/authorize accessor=<BOBS_WRAPPING_ACCESSOR>

# Login as bob
vault login -method=userpass username="bob" password="training"

# Unwrap bob's wrapping_token
vault unwrap <BOBS_WRAPPING_TOKEN>
