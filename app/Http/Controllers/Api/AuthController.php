<?php

namespace App\Http\Controllers\Api;

use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    /**
     * @OA\Post(
     * path="/api/auth/register",
     * tags={"Auth"},
     * summary="user registeration",
     * description="A user registers on the platform",
     *     @OA\RequestBody(
     *         @OA\MediaType(
     *            mediaType="application/json",
     *            @OA\Schema(
     *               type="object",
     *               required={"name","email"},
     *               @OA\Property(property="name", type="string"),
     *               @OA\Property(property="email", type="string")
     *               @OA\Property(property="phone number", type="integer")
     *               @OA\Property(property="password", type="string")
     *            ),
     *        ),
     *    ),
     *      @OA\Response(
     *          response=201,
     *          description="Added Successfully",
     *          @OA\JsonContent()
     *       ),
     *      @OA\Response(
     *          response=422,
     *          description="Unprocessable Entity",
     *          @OA\JsonContent()
     *       ),
     *      @OA\Response(response=400, description="Bad request"),
     *      @OA\Response(response=404, description="Resource Not Found"),
     * )
     */
    public function register(Request $request)
    {

        $validator = Validator::make($request->all(), [
            'name' => 'required|string',
            'email' => 'required|unique:users|email',
            'phone_number' => 'required|unique:users|digits:11',
            'password' => 'required|string|min:4'
        ]);

        if ($validator->fails()) {
            $response = [
                'status' => 'failure',
                'status_code' => 400,
                'errors' => $validator->errors(),
            ];
            return response()->json($response, 400);
        } else {
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'phone_number' => $request->phone_number,
                'password' => Hash::make($request->password),
            ]);
            if ($user) {
                $token = $user->createToken('auth_token')->plainTextToken;
                $response = [
                    'user' => $user,
                    'token' => $token
                ];
                return response($response, 200);
            }
        }
    }


    /**
     * @OA\Post(
     * path="/api/auth/login",
     * tags={"Auth"},
     * summary="user login",
     * description="A user enters login details",
     *     @OA\RequestBody(
     *         @OA\MediaType(
     *            mediaType="application/json",
     *            @OA\Schema(
     *               type="object",
     *               required={"email or password","password"},
     *               @OA\Property(property="email or password", type="string"),
     *               @OA\Property(property="password", type="string")
     *            ),
     *        ),
     *    ),
     *      @OA\Response(
     *          response=201,
     *          description="login successful",
     *          @OA\JsonContent()
     *       ),
     *      @OA\Response(
     *          response=422,
     *          description="login fails",
     *          @OA\JsonContent()
     *       ),
     *      @OA\Response(response=400, description="Bad request"),
     *      @OA\Response(response=404, description="Resource Not Found"),
     * )
     */
    public function login(Request $request)
    {
        $user = User::where('email', $request->email)->orWhere('phone_number', $request->phone_number)->first();
        if (!$user || !Hash::check($request->password, $user->password)) {
            return response([
                'message' => 'incorrect login details'
            ], 401);
        } else {
            $token = $user->createToken('myapptoken')->plainTextToken;
            return response([
                'user' => $user,
                'token' => $token
            ], 200);
        }
    }


    /**
     * @OA\Post(
     * path="/api/logout/",
     * tags={"Auth"},
     * summary="loggout user",
     * description="A user logs out of the platform",
     *     @OA\RequestBody(
     *         @OA\MediaType(
     *            mediaType="application/json",
     *            @OA\Schema(
     *               type="object",
     *            ),
     *        ),
     *    ),
     *      @OA\Response(
     *          response=201,
     *          description="log out Successfully",
     *          @OA\JsonContent()
     *       ),
     *      @OA\Response(
     *          response=422,
     *          description="Unprocessable Entity",
     *          @OA\JsonContent()
     *       ),
     *      @OA\Response(response=400, description="Bad request"),
     *      @OA\Response(response=404, description="Resource Not Found"),
     * )
     */

    public function logout(Request $request)
    {
        $request->user()->token()->delete();
        return response()->json([
            'message' => 'Successfully logged out'
        ]);
    }
}
