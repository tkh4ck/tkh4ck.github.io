import boto3

client = boto3.client('dynamodb',
               region_name='us-east-2',
               endpoint_url='http://cloud.htb',
               aws_access_key_id='',
               aws_secret_access_key=''
               )

client.create_table(TableName='users',
        KeySchema=[
            {
                'AttributeName': 'username',
                'KeyType': 'HASH'
            },
	    {
		'AttributeName': 'password',
		'KeyType': 'RANGE'
	    },
        ],
        AttributeDefinitions=[
            {
                'AttributeName': 'username',
                'AttributeType': 'S'
            },
	    {
		'AttributeName': 'password',
		'AttributeType': 'S'
	    },
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5,
        }
	)


client.put_item(TableName='users',
	Item={
		'username': {
			'S': 'marcus'
		},
		'password': {
			'S': 'dFc42BvUs02'
		},
	}
	)
