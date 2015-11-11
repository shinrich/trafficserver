/** @file

  Basic generic callback support until we require C++ eleventy.

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#if !defined(TS_LAMBDA_H)
#define TS_LAMBDA_H

#include <new>

/** Base class for lambda holders.

    This just declares the storage so the calculation doesn't have to be cut and pasted over and over.
*/
struct Lambda {
  /// Generic version of struct used in subclasses to get size correct.
  struct Generic {
    virtual void method() = 0; // force virtual method to get sizing correct.
    Lambda *_obj;
    void (Lambda::*_ptom)();
    virtual ~Generic() {} // Make compiler shut up.
  };

protected:
  /// A block of data big enough to hold a pointer to an object and a pointer to method
  /// of that object.
  uint8_t data[sizeof(Generic)];

  Lambda() { ink_zero(data); }
  virtual ~Lambda() {} // make compiler shut up.

public:
  operator bool() const { return 0 != reinterpret_cast<void const *>(data); }
  bool operator!() const { return 0 == reinterpret_cast<void const *>(data); }
};

/** Zero argument lambda.

    This contains a lambda that returns @a R and takes no arguments.
*/
template <typename R> struct Lambda_0 : public Lambda {
private:
  /// Internal base that isolates invocation from the object and member pointer types.
  struct L {
    virtual R invoke() = 0;
    virtual ~L() {} // make compiler shut up.
  };

public:
  /// Assign a callback method @a ptom on the object @a obj as the lambda.
  template <typename C>
  void
  assign(C *obj, R (C::*ptom)())
  {
    /// Embed the type information for @a obj and @a ptom in a class which can be
    /// invoked through the non-type dependent base class @c L.
    struct I : public L {
      C *_obj;                                          ///< The object.
      R (C::*_ptom)();                                  ///< Pointer to member of object.
      I(C *c, R (C::*ptom)()) : _obj(c), _ptom(ptom) {} ///< Constructor.

      /// Invoke the lambda.
      R
      invoke()
      {
        return (_obj->*_ptom)();
      }
    };
    /// Embed the class in the generic storage via placement new.
    new (data) I(obj, ptom);
  }

  /// Assign a free function @a func as the lambda.
  void assign(R (*func)())
  {
    /// Embed the function.
    struct I : public L {
      R (*_func)();                   ///< Free function pointer.
      I(R (*func)()) : _func(func) {} ///< Constructor.

      /// Call the function.
      R
      invoke()
      {
        return _func();
      }
    };
    /// Embed the class in the generic storage via placement new.
    new (data) I(func);
  }
  /// Call the embedded lambda.
  R operator()() { return reinterpret_cast<L *>(data)->invoke(); }
};

/** One argument lambda.

    This contains a lambda that returns @a R and takes a single argument of type @a A1.
*/
template <typename R, typename A1> struct Lambda_1 : public Lambda {
private:
  /// Internal base that isolates invocation from the object and member pointer types.
  struct L {
    virtual R invoke(A1) = 0;
    virtual ~L() {} // make compiler shut up.
  };

public:
  /// Assign a callback method @a ptom on the object @a obj as the lambda.
  template <typename C>
  void
  assign(C *obj, R (C::*ptom)(A1))
  {
    /// Embed the type information for @a obj and @a ptom in a class which can be
    /// invoked through the non-type dependent base class @c L.
    struct I : public L {
      C *_obj;                                            ///< The object.
      R (C::*_ptom)(A1);                                  ///< Pointer to member of object.
      I(C *c, R (C::*ptom)(A1)) : _obj(c), _ptom(ptom) {} ///< Constructor.

      /// Invoke the lambda.
      R
      invoke(A1 a1)
      {
        return (_obj->*_ptom)(a1);
      }
    };
    /// Embed the class in the generic storage via placement new.
    new (data) I(obj, ptom);
  }

  /// Assign a free function @a func as the lambda.
  void assign(R (*func)(A1))
  {
    /// Embed the function.
    struct I : public L {
      R (*_func)(A1);                   ///< Free function pointer.
      I(R (*func)(A1)) : _func(func) {} ///< Constructor.

      /// Call the function.
      R
      invoke(A1 a1)
      {
        return _func(a1);
      }
    };
    /// Embed the class in the generic storage via placement new.
    new (data) I(func);
  }
  /// Call the embedded lambda.
  R operator()(A1 a1) { return reinterpret_cast<L *>(data)->invoke(a1); }
};

#endif
