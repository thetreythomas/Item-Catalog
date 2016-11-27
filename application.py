from functools import wraps
from flask import Flask, render_template, request, redirect, jsonify, url_for, flash

from sqlalchemy import create_engine, asc, desc, func
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Catalog, CatalogItem, User


app = Flask(__name__)

#Items for Anti Forgery State Token
from flask import session as login_session
import random, string


#Items for Google Login
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog Application"


# Connect to the database and create the database session
engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


###############
#             #
# Login Check #
#             #
###############

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = login_session.get('username')
        if user is None:
            return redirect(url_for('showCatalogs'))
        return f(*args, **kwargs)
    return decorated_function



# Creates a state token to prevent request forgery
# Store it in the session for later validation
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    print "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)

@app.route('/gconnect', methods=['POST'])
def connect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade the authorization code.'), 402)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # Verify that the access token is used for the intended user
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps("Token's user ID doesn't match given user ID"), 403)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps("Token's client ID doesn't match app's"), 404)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check to see if the user is already logged in
    #stored_credentials = login_session.get('credentials')
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # See if user exists, if it doesn't make a new user record
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output



# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session['access_token']
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        login_session.clear()
        #del login_session['access_token']
        #del login_session['gplus_id']
        #del login_session['username']
        #del login_session['email']
        #del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        flash ('User is logged out successfully.')
        return redirect(url_for('showCatalogs'))
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


###############
#             #
#  Catalog    #
#             #
###############


#SHOW ALL CATALOGS
@app.route('/')
@app.route('/catalogs/', methods=['GET', 'POST'])
def showCatalogs():
    #if 'username' not in login_session:
    #    return redirect('/login')
    if 'username' in login_session:
        user = session.query(User).filter_by(name = login_session['username']).one()
    else:
        user = None
    items = session.query(CatalogItem).order_by(CatalogItem.id.desc()).limit(5).all()
    catalogs = session.query(Catalog).all()
    return render_template('catalogs.html', catalogs = catalogs, user = user, items = items)



#SHOW ALL ITEMS on a catalog using the string
@app.route('/catalog/<catalog_name>/')
@app.route('/catalog/<catalog_name>/items/')
def showCatalogItems(catalog_name):
    if 'username' in login_session:
        user = session.query(User).filter_by(name = login_session['username']).one()
    else:
        user = None
    catalog = session.query(Catalog).filter_by(name=catalog_name).one()
    items = session.query(CatalogItem).filter_by(catalog_id=catalog.id).all()
    catalogs = session.query(Catalog).all()
    count = session.query(CatalogItem).join(Catalog).filter_by(id = catalog.id).count()
    return render_template('catalog.html', catalog=catalog, items=items, user=user, catalogs = catalogs, count = count)



#ADD ITEM to the list of catalogs
@app.route('/catalog/new/', methods=['GET', 'POST'])
@app.route('/catalogs/new/', methods=['GET', 'POST'])
@login_required
def addNewCatalog():
    if request.method == 'POST':
        newCatalog = Catalog(name=request.form['name'])
        session.add(newCatalog)
        session.commit()
        flash("New Catalog Created!")
        return redirect(url_for('showCatalogs'))
    else:
        return render_template('newCatalog.html')



###############
#             #
#    Items    #
#             #
###############



#SHOW SINGLE ITEM information
@app.route('/catalog/<catalog_name>/item/<int:item_id>/')
def showItem(catalog_name, item_id):
    if 'username' in login_session:
        user = session.query(User).filter_by(name = login_session['username']).one()
    else:
        user = None
    catalog = session.query(Catalog).filter_by(name=catalog_name).one()
    item = session.query(CatalogItem).filter_by(id=item_id).one()
    return render_template('showItem.html', catalog = catalog, item = item, user = user)



#ADD NEW ITEM to an existing catalog
@app.route('/catalog/<catalog_name>/item/add/', methods=['GET', 'POST'])
@login_required
def addNewItem(catalog_name):
    catalog = session.query(Catalog).filter_by(name=catalog_name).one()
    catalogID = catalog.id
    if request.method == 'POST':
        newItem = CatalogItem(item_name = request.form['name'],
                              description = request.form['description'],
                              catalog_id = catalog.id,
                              user_id = login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash("New Item Added to Catalog!")
        return redirect(url_for('showCatalogItems', catalog_name = catalog_name))
    else:
        return render_template('addItem.html', catalog = catalog, catalog_name=catalog_name)



#EDIT AN ITEM from an existing catalog
@app.route('/catalog/<catalog_name>/item/<int:item_id>/edit/', methods=['GET', 'POST'])
@login_required
def editItem(catalog_name, item_id):
    catalog = session.query(Catalog).filter_by(name=catalog_name).one()
    item = session.query(CatalogItem).filter_by(id=item_id).one()
    if request.method == "POST":
        if request.form['name']:
            item.item_name = request.form['name']
            item.description = request.form['description']
            session.add(item)
            session.commit()
            flash ("Item has been updated.")
            return redirect(url_for('showItem', catalog_name = catalog.name, item_id = item.id))
    else:
        return render_template('editItem.html', catalog = catalog, item = item)



#DELETE AN ITEM from an existing catalog
@app.route('/catalog/<catalog_name>/item/<int:item_id>/delete/', methods=['GET', 'POST'])
@login_required
def deleteItem(catalog_name, item_id):
    catalog = session.query(Catalog).filter_by(name=catalog_name).one()
    itemToDelete = session.query(CatalogItem).filter_by(id=item_id).one()

    if 'username' not in login_session:
        return redirect('/login')
    if itemToDelete.user_id != login_session['user_id']:
        return "<script> function myFunction() {alert('You are not authorized to delete this item.');}" \
               "</script><body onload='myFunction()''>"
    if request.method == "POST":
        session.delete(itemToDelete)
        session.commit()
        flash ("Item %s has been DELETED." % itemToDelete.item_name)
        return redirect(url_for('showCatalogs'))
    else:
        return render_template('deleteItem.html', catalog = catalog, item = itemToDelete)




###############
#             #
# JSON APIs   #
#             #
###############

@app.route('/json')
@app.route('/catalogs/json')
def showCatalogsJSON():
    catalogs = session.query(Catalog).all()
    return jsonify(Catalogs=[c.serialize for c in catalogs])


@app.route('/catalog/<catalog_name>/json')
@app.route('/catalog/<catalog_name>/items/json')
def showCatalogItemsJSON(catalog_name):
    catalog = session.query(Catalog).filter_by(name=catalog_name).one()
    items = session.query(CatalogItem).filter_by(catalog_id=catalog.id).all()
    return jsonify(CatalogItems=[i.serialize for i in items])





###############
#             #
# User Setup  #
#             #
###############

def getUserInfo(user_id):
    user = session.query(User).filter_by(id = user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email = email).one()
        return user.id
    except:
        return None


def createUser(login_session):
    newUser = User(name = login_session['username'], email = login_session['email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email = login_session['email']).one()
    return user.id



###############
#             #
#   Config    #
#             #
###############





if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host = '0.0.0.0', port = 8000)