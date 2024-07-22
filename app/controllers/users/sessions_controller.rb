# frozen_string_literal: true

class Users::SessionsController < Devise::SessionsController
  respond_to :json

  def create
    user = User.find_by(email: params[:user][:email])

    if user&.valid_password?(params[:user][:password])
      sign_in(user)
      token = encode_jwt(user)
      render json: {
        status: {
          code: 200,
          message: 'Logged in successfully.',
          data: { user: UserSerializer.new(user).serializable_hash[:data][:attributes], token: token }
        }
      }, status: :ok
    else
      render json: { error: 'Invalid email or password' }, status: :unauthorized
    end
  end

  def destroy
    if request.headers['Authorization'].present?
      begin
        jwt_payload = JWT.decode(request.headers['Authorization'].split(' ').last, Rails.application.credentials.devise_jwt_secret_key!).first
        user = User.find(jwt_payload['sub'])
      rescue JWT::DecodeError, ActiveRecord::RecordNotFound
        user = nil
      end
    end

    if user
      sign_out(user)
      render json: {
        status: 200,
        message: 'Logged out successfully.'
      }, status: :ok
    else
      render json: {
        status: 401,
        message: "Couldn't find an active session."
      }, status: :unauthorized
    end
  end

  private

  def encode_jwt(user)
    payload = { sub: user.id, exp: 24.hours.from_now.to_i }
    JWT.encode(payload, Rails.application.credentials.devise_jwt_secret_key!)
  end

  def decode_jwt(token)
    JWT.decode(token, Rails.application.credentials.devise_jwt_secret_key!, true, algorithm: 'HS256')
  rescue JWT::DecodeError
    nil
  end
end
